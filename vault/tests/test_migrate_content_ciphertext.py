from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.cache import cache
from vault.models import UserVault, SecretItem
from vault.crypto import generate_dek, encrypt_dek_with_password, encrypt_with_dek, decrypt_dek_with_password
import os
import base64

class MigrateCiphertextCommandTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.password = 'pass123'
        self.user = User.objects.create_user(username='migrate_user', password=self.password)
        salt = os.urandom(16)
        dek = generate_dek()
        uv, _ = UserVault.objects.get_or_create(user=self.user)
        uv.dek_salt = salt
        uv.dek_encrypted = encrypt_dek_with_password(dek, self.password, salt)
        uv.save()
        # Create a properly encrypted item (server-side)
        enc = encrypt_with_dek(dek, 'server secret')
        SecretItem.objects.create(owner=self.user, title='Good', item_type='SECRET', content_encrypted=enc)
        # Create a client-encrypted base64 item incorrectly stored in content
        client_ct = encrypt_with_dek(dek, 'client secret')
        b64ct = base64.b64encode(client_ct).decode()
        SecretItem.objects.create(owner=self.user, title='ClientBad', item_type='SECRET', content=b64ct)

    def test_dry_run_detects_candidate(self):
        import io
        out = io.StringIO()
        call_command('migrate_content_ciphertext', '--dry-run', stdout=out)
        # Should detect one candidate
        self.assertIn('Found 1 candidate(s) for migration', out.getvalue())

    def test_commit_migrates(self):
        call_command('migrate_content_ciphertext', '--commit')
        item = SecretItem.objects.get(owner=self.user, title='ClientBad')
        self.assertEqual(item.content, '')
        self.assertIsNotNone(item.content_encrypted)
