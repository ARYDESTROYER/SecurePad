from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from django.core.cache import cache

from vault.crypto import generate_dek, encrypt_dek_with_password, encrypt_with_dek, decrypt_with_dek
from vault.models import UserVault, SecretItem
import os


class ReauthVaultTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.username = 'reauthuser'
        self.password = 'password123'
        self.user = User.objects.create_user(username=self.username, password=self.password)
        # create a vault profile and an encrypted DEK
        salt = os.urandom(16)
        dek = generate_dek()
        uv, _ = UserVault.objects.get_or_create(user=self.user)
        uv.dek_salt = salt
        uv.dek_encrypted = encrypt_dek_with_password(dek, self.password, salt)
        uv.save()
        # create an encrypted SecretItem for this user
        si = SecretItem.objects.create(owner=self.user, title='E1', item_type='NOTE', content_encrypted=encrypt_with_dek(dek, 'This is a secret'))

    def test_reauth_fails_with_wrong_password(self):
        # Login via POST to ensure request.POST contains password and DEK is set (mimicking real flow)
        login_response = self.client.post(reverse('login'), {'username': self.username, 'password': self.password}, follow=True)
        self.assertEqual(login_response.status_code, 200)
        # Ensure cache cleared
        sk = self.client.session.session_key
        cache.delete(f'dek:{sk}')
        resp = self.client.post(reverse('vault:reauth_vault'), {'password': 'wrongpass'})
        self.assertEqual(resp.status_code, 403)
        self.assertIn('invalid_password', resp.json().get('error', ''))

    def test_reauth_succeeds_with_correct_password_and_caches_dek(self):
        login = self.client.login(username=self.username, password=self.password)
        self.assertTrue(login)
        sk = self.client.session.session_key
        # delete cache to simulate expired DEK
        cache.delete(f'dek:{sk}')
        resp = self.client.post(reverse('vault:reauth_vault'), {'password': self.password})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json().get('status'), 'ok')
        # Check the cache has dek
        cached = cache.get(f'dek:{sk}')
        self.assertIsNotNone(cached)
        # Now the dashboard should decrypt the secret in content
        dash = self.client.get(reverse('vault:dashboard'))
        self.assertContains(dash, 'This is a secret')

    def test_get_raw_dek_returns_32_byte_key(self):
        # Login + simulate cached dek
        login = self.client.login(username=self.username, password=self.password)
        self.assertTrue(login)
        sk = self.client.session.session_key
        # The login flow should have already cached the DEK; verify it's present
        # If not present, try the reauth flow to set it
        from django.core.cache import cache as djcache
        cached = djcache.get(f'dek:{sk}')
        if not cached:
            # Call reauth endpoint to set it via password
            self.client.post(reverse('vault:reauth_vault'), {'password': self.password})
        r = self.client.get(reverse('vault:get_raw_dek'))
        self.assertEqual(r.status_code, 200)
        data = r.json()
        from base64 import urlsafe_b64decode
        key_bytes = urlsafe_b64decode(data.get('dek'))
        # Expect 32 bytes (256-bit key)
        self.assertEqual(len(key_bytes), 32)
