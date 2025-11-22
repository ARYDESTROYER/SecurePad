from django.contrib import admin
from .models import SecretItem
from django.core.cache import cache
from .crypto import encrypt_with_dek

@admin.register(SecretItem)
class SecretItemAdmin(admin.ModelAdmin):
    list_display = ('title', 'item_type', 'owner', 'created_at', 'content_preview')
    list_filter = ('item_type', 'created_at')
    search_fields = ('title', 'owner__username')

    def content_preview(self, obj):
        # Show some snippet; if decrypted available in cache, decrypt, otherwise show 'Encrypted'
        from django.core.cache import cache
        sk = self.request.session.session_key if hasattr(self, 'request') else None
        if sk:
            dek = cache.get(f'dek:{sk}')
        else:
            dek = None
        if obj.content_encrypted and dek:
            try:
                from .crypto import decrypt_with_dek
                return decrypt_with_dek(dek, obj.content_encrypted)[:60]
            except Exception:
                return '[Encrypted]'
        return (obj.content or '')[:60]
    content_preview.short_description = 'Content'
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        # Keep a reference to the request so list display functions can use it
        self.request = request
        # Only show objects that belong to the current user
        if request.user.is_authenticated:
            return qs.filter(owner=request.user)
        return qs.none()

    actions = ['migrate_client_ciphertext']

    def migrate_client_ciphertext(self, request, queryset):
        import base64
        migrated = 0
        for item in queryset:
            if item.content and not item.content_encrypted:
                try:
                    decoded = base64.b64decode(item.content)
                except Exception:
                    try:
                        decoded = base64.urlsafe_b64decode(item.content)
                    except Exception:
                        decoded = None
                if decoded and len(decoded) > 16:
                    item.content_encrypted = decoded
                    item.content = ''
                    item.save(update_fields=['content', 'content_encrypted'])
                    migrated += 1
        self.message_user(request, f'Migrated {migrated} item(s)')
    migrate_client_ciphertext.short_description = 'Migrate selected client ciphertext stored in content into content_encrypted'    

    def save_model(self, request, obj, form, change):
        # If content is in plaintext, encrypt with the user's DEK cached in session
        sk = request.session.session_key
        if not sk:
            request.session.save()
            sk = request.session.session_key
        dek = cache.get(f'dek:{sk}')
        if dek and obj.content:
            obj.content_encrypted = encrypt_with_dek(dek, obj.content)
            obj.content = ''
        # Ensure the owner defaults to request.user if not set
        if not obj.owner:
            obj.owner = request.user
        super().save_model(request, obj, form, change)
