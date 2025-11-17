from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from django.contrib.messages import get_messages


class DecryptingMessageTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.username = 'testuser'
        self.password = 'password123'
        self.user = User.objects.create_user(username=self.username, password=self.password)

    def test_decrypting_message_shown_once_after_login(self):
        login_url = reverse('login')
        dashboard_url = reverse('vault:dashboard')
        # Create an encrypted item for the user so the banner should appear
        from vault.models import SecretItem
        SecretItem.objects.create(owner=self.user, title='E1', item_type='NOTE', content_encrypted=b'encrypted')
        # Login via POST and follow redirect — response should include the decrypting message
        response = self.client.post(login_url, {'username': self.username, 'password': self.password}, follow=True)
        # Get messages from the response's request context
        messages = list(get_messages(response.wsgi_request))
        message_texts = [str(m) for m in messages]
        self.assertIn('Decrypting your notes, please wait...', message_texts)
        # The message should be tagged for auto-dismiss
        tags = [m.tags for m in messages]
        self.assertTrue(any('auto-dismiss' in str(t) for t in tags))

        # Next GET should not contain the message (it was popped from session during the redirect)
        response = self.client.get(dashboard_url)
        messages = list(get_messages(response.wsgi_request))
        message_texts = [str(m) for m in messages]
        self.assertNotIn('Decrypting your notes, please wait...', message_texts)
        # Logout and re-login should show the message again once (we check messages on login response)
        self.client.get(reverse('logout'))
        response = self.client.post(login_url, {'username': self.username, 'password': self.password}, follow=True)
        messages = list(get_messages(response.wsgi_request))
        message_texts = [str(m) for m in messages]
        self.assertIn('Decrypting your notes, please wait...', message_texts)
        # Next GET still should not contain the message
        response = self.client.get(dashboard_url)
        messages = list(get_messages(response.wsgi_request))
        message_texts = [str(m) for m in messages]
        self.assertNotIn('Decrypting your notes, please wait...', message_texts)

    def test_no_message_for_users_without_encrypted_items(self):
        # User without encrypted items should not see the decrypting banner
        from django.urls import reverse
        login_url = reverse('login')
        dashboard_url = reverse('vault:dashboard')
        self.client.post(login_url, {'username': self.username, 'password': self.password}, follow=True)
        # Login response should not include the message
        response = self.client.get(dashboard_url)
        messages = list(get_messages(response.wsgi_request))
        message_texts = [str(m) for m in messages]
        self.assertNotIn('Decrypting your notes, please wait...', message_texts)
