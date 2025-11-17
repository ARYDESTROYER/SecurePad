from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.cache import cache
from .crypto import decrypt_with_dek

class SecretItem(models.Model):
    NOTE = 'NOTE'
    SECRET = 'SECRET'
    ENV = 'ENV'

    ITEM_TYPE_CHOICES = [
        (NOTE, 'Note'),
        (SECRET, 'Secret'),
        (ENV, 'Env Variable'),
    ]

    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='secret_items')
    title = models.CharField(max_length=200)
    # Content will be encrypted; store ciphertext in binary field
    content = models.TextField(null=True, blank=True)  # legacy plaintext (for migration)
    content_encrypted = models.BinaryField(null=True, editable=False)
    item_type = models.CharField(max_length=10, choices=ITEM_TYPE_CHOICES, default=NOTE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} ({self.item_type})"

    @property
    def decrypted_content(self):
        # Attempt to decrypt using cached user's DEK
        if self.content_encrypted:
            # try to get current user's session-keyed DEK from cache; fall back to not interrupting
            # we don't have request context here; the view should handle decryption where request is present.
            return '<encrypted>'
        return self.content or ''


class UserVault(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='vault_profile')
    dek_encrypted = models.BinaryField(null=True, blank=True)
    dek_salt = models.BinaryField(null=True, blank=True)
    dek_kdf_iterations = models.IntegerField(default=200_000)

    def __str__(self):
        return f"Vault profile for {self.user.username}"

