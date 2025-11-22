from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from django.core.cache import cache

from vault.crypto import generate_dek, encrypt_dek_with_password
from vault.models import UserVault, SecretItem
import os


class CreateItemTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.username = 'createuser'
        self.password = 'password123'
        self.user = User.objects.create_user(username=self.username, password=self.password)
        # create a vault profile and an encrypted DEK and legacy item
        salt = os.urandom(16)
        dek = generate_dek()
        uv, _ = UserVault.objects.get_or_create(user=self.user)
        uv.dek_salt = salt
        uv.dek_encrypted = encrypt_dek_with_password(dek, self.password, salt)
        uv.save()

    def test_create_plaintext_item_without_cached_dek_is_rejected(self):
        login = self.client.login(username=self.username, password=self.password)
        self.assertTrue(login)
        sk = self.client.session.session_key
        # Ensure DEK not cached to simulate idle expiry
        cache.delete(f'dek:{sk}')
        post_data = {'title': 'Plain1', 'content': 'plaintext content', 'item_type': 'NOTE', 'is_ciphertext': '0'}
        resp = self.client.post(reverse('vault:create_item'), post_data, follow=True)
        # should render create form again (status 200) with error message
        self.assertEqual(resp.status_code, 200)
        self.assertIn('dek_present', resp.context)
        self.assertFalse(resp.context['dek_present'])
        # no item should have been created
        self.assertFalse(SecretItem.objects.filter(owner=self.user, title='Plain1').exists())

    def test_create_plaintext_item_with_cached_dek_succeeds(self):
        login = self.client.login(username=self.username, password=self.password)
        self.assertTrue(login)
        sk = self.client.session.session_key
        # Simulate user login flow cached DEK (decrypt using password)
        from vault.crypto import decrypt_dek_with_password
        uv = self.user.vault_profile
        uv.refresh_from_db()
        uv.refresh_from_db()
        from vault.crypto import decrypt_dek_with_password
        dek = decrypt_dek_with_password(uv.dek_encrypted, self.password, bytes(uv.dek_salt))
        cache.set(f'dek:{sk}', dek, timeout=300)

        post_data = {'title': 'Plain2', 'content': 'plaintext content', 'item_type': 'NOTE', 'is_ciphertext': '0'}
        resp = self.client.post(reverse('vault:create_item'), post_data, follow=True)
        # Should render item_detail page for the created item
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(SecretItem.objects.filter(owner=self.user, title='Plain2').exists())

    def test_create_client_ciphertext_item_stored(self):
        # Check server accepts and stores base64 client ciphertext
        login_response = self.client.post(reverse('login'), {'username': self.username, 'password': self.password}, follow=True)
        self.assertEqual(login_response.status_code, 200)
        # Compose a fake client ciphertext (server doesn't validate it beyond storing binary)
        from base64 import b64encode
        ct = b'pretend-ciphertext'
        b64ct = b64encode(ct).decode()
        post_data = {'title': 'Client1', 'content': b64ct, 'item_type': 'SECRET', 'is_ciphertext': '1'}
        resp = self.client.post(reverse('vault:create_item'), post_data, follow=True)
        self.assertEqual(resp.status_code, 200)
        obj = SecretItem.objects.get(owner=self.user, title='Client1')
        self.assertIsNotNone(obj.content_encrypted)

    def test_item_detail_shows_error_on_decryption_failure(self):
        # Create a secret encrypted with a different key (so decrypt fails)
        login_response = self.client.post(reverse('login'), {'username': self.username, 'password': self.password}, follow=True)
        self.assertEqual(login_response.status_code, 200)
        # Create a SecretItem with random bytes in content_encrypted so decrypt will fail
        bad = SecretItem.objects.create(owner=self.user, title='BadSecret', item_type='SECRET', content_encrypted=b'random-bytes')
        # Access item_detail - since dek is cached at login, item_detail will try decrypt and fail
        r = self.client.get(reverse('vault:item_detail', args=(bad.pk,)))
        self.assertEqual(r.status_code, 200)
        # The page should contain our error string
        self.assertContains(r, 'Error decrypting')
        # Ensure the page contains the encrypted_b64 data attribute so client-side can attempt decrypt
        self.assertIn('data-ct="', r.content.decode())

    def test_dashboard_flags_client_ciphertext(self):
        # Create a client ciphertext saved in content earlier
        dek = None
        uv = self.user.vault_profile
        if uv.dek_encrypted:
            from vault.crypto import decrypt_dek_with_password
            dek = decrypt_dek_with_password(uv.dek_encrypted, self.password, uv.dek_salt)
        # Create a base64 content-looking item
        import base64
        test_ct = base64.b64encode(b'randomct' * 5).decode()
        SecretItem.objects.create(owner=self.user, title='LikelyCipher', item_type='SECRET', content=test_ct)
        login_response = self.client.post(reverse('login'), {'username': self.user.username, 'password': self.password}, follow=True)
        self.assertEqual(login_response.status_code, 200)
        r = self.client.get(reverse('vault:dashboard'))
        self.assertContains(r, 'client-side ciphertext')

    def test_duplicate_post_does_not_create_two_items(self):
        # Ensure DEK present
        login_response = self.client.post(reverse('login'), {'username': self.user.username, 'password': self.password}, follow=True)
        self.assertEqual(login_response.status_code, 200)
        sk = self.client.session.session_key
        # Ensure dek cached
        from vault.crypto import decrypt_dek_with_password
        uv = self.user.vault_profile
        uv.refresh_from_db()
        salt = uv.dek_salt
        if salt is None:
            self.fail('UserVault dek_salt not present')
        if not isinstance(salt, (bytes, bytearray)):
            salt = bytes(salt)
        dek = decrypt_dek_with_password(uv.dek_encrypted, self.password, salt)
        cache.set(f'dek:{sk}', dek, timeout=300)

        # Add the same submission_id for both posts to simulate a double-click duplicate
        sid = 'test-sid-1234'
        post_data = {'title': 'Dupe', 'content': 'dup content', 'item_type': 'NOTE', 'is_ciphertext': '0', 'submission_id': sid}
        # Post twice rapidly
        resp1 = self.client.post(reverse('vault:create_item'), post_data)
        resp2 = self.client.post(reverse('vault:create_item'), post_data)
        self.assertTrue(SecretItem.objects.filter(owner=self.user, title='Dupe').count() == 1)
        # Second response should redirect to the existing item detail
        self.assertEqual(resp2.status_code, 302)

    def test_submission_inflight_prevents_duplicate_creation(self):
        login_response = self.client.post(reverse('login'), {'username': self.user.username, 'password': self.password}, follow=True)
        self.assertEqual(login_response.status_code, 200)
        sk = self.client.session.session_key
        from vault.crypto import decrypt_dek_with_password
        uv = self.user.vault_profile
        uv.refresh_from_db()
        salt = uv.dek_salt
        if not isinstance(salt, (bytes, bytearray)):
            salt = bytes(salt)
        dek = decrypt_dek_with_password(uv.dek_encrypted, self.password, salt)
        cache.set(f'dek:{sk}', dek, timeout=300)

        sid = 'race-guard-sid'
        cache.set(f'submission:{sid}', 'inflight', timeout=60)
        post_data = {'title': 'Guarded', 'content': 'guard content', 'item_type': 'NOTE', 'is_ciphertext': '0', 'submission_id': sid}
        resp = self.client.post(reverse('vault:create_item'), post_data)
        # Request should be redirected without creating an item
        self.assertEqual(resp.status_code, 302)
        self.assertFalse(SecretItem.objects.filter(owner=self.user, title='Guarded').exists())
        cache.delete(f'submission:{sid}')
