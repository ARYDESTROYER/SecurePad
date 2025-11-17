from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from django.core.cache import cache
from .models import UserVault, SecretItem
from .crypto import generate_dek, decrypt_dek_with_password, encrypt_dek_with_password, encrypt_with_dek
import os


@receiver(post_save, sender=User)
def create_user_vault(sender, instance, created, **kwargs):
    if created:
        UserVault.objects.create(user=instance)


@receiver(user_logged_in)
def ensure_user_vault(sender, user, request, **kwargs):
    # Attempt to make sure this user's vault is initialized and cached DEK is set.
    uv, _ = UserVault.objects.get_or_create(user=user)
    # If no encrypted DEK exists, create it using the password from request POST if present
    password = None
    try:
        # For login via POST form, the password may be present in POST (not in other flows)
        password = request.POST.get('password')
    except Exception:
        password = None
    dek = None
    if not uv.dek_encrypted and password:
        salt = os.urandom(16)
        dek = generate_dek()
        uv.dek_salt = salt
        uv.dek_encrypted = encrypt_dek_with_password(dek, password, salt)
        uv.save()
        # Re-encrypt legacy content
        legacy_items = SecretItem.objects.filter(owner=user).exclude(content='')
        for li in legacy_items:
            try:
                li.content_encrypted = encrypt_with_dek(dek, li.content)
                li.content = ''
                li.save()
            except Exception:
                pass
    else:
        if uv.dek_encrypted and password:
            try:
                dek = decrypt_dek_with_password(uv.dek_encrypted, password, uv.dek_salt)
            except Exception:
                dek = None
    if dek:
        sk = request.session.session_key
        if not sk:
            request.session.save()
            sk = request.session.session_key
        cache.set(f'dek:{sk}', dek, timeout=300)
        # Only set the 'show_decrypting' flag if we haven't shown it yet for this session
        # and only if there are encrypted items to decrypt (or we just migrated legacy plaintext)
        has_encrypted = SecretItem.objects.filter(owner=user, content_encrypted__isnull=False).exists()
        # If we created/rewrote legacy items to encrypted, show the banner to indicate migration.
        legacy_items_exist = SecretItem.objects.filter(owner=user).exclude(content='').exists()
        if (has_encrypted or legacy_items_exist) and not request.session.get('show_decrypting') and not request.session.get('show_decrypting_shown'):
            request.session['show_decrypting'] = True
