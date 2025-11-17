from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404
from django.db.models import Q
from django.contrib.auth import views as auth_views
from django.core.cache import cache
from django.contrib import messages
from .models import SecretItem, UserVault
from .crypto import (generate_dek, decrypt_dek_with_password,
                     encrypt_dek_with_password, decrypt_with_dek)
from django.contrib.auth import views as auth_views
from django.http import JsonResponse, HttpResponseForbidden
from django.utils.encoding import force_bytes
from base64 import b64encode, b64decode
from .forms import SecretItemForm
from .crypto import encrypt_with_dek

@login_required
def dashboard(request):
    items_qs = SecretItem.objects.filter(owner=request.user)
    q = request.GET.get('q', '').strip()
    if q:
        items_qs = items_qs.filter(Q(title__icontains=q))

    # decrypt items for display if DEK available in session cache
    dek = cache.get(f'dek:{request.session.session_key}')
    # Show the decrypting message once if it was set by the login flow; pop it off session
    show_once = request.session.pop('show_decrypting', False)
    if show_once:
        messages.info(request, 'Decrypting your notes, please wait...', extra_tags='auto-dismiss')
        # Mark that we've shown the message already so it cannot be set again during this session
        request.session['show_decrypting_shown'] = True
    items = []
    for item in items_qs:
        if item.content_encrypted and dek:
            try:
                item.decrypted_display = decrypt_with_dek(dek, item.content_encrypted)
            except Exception:
                item.decrypted_display = '<error decrypting>'
        else:
            item.decrypted_display = item.content or ''
        items.append(item)
    # Count encrypted items for UI messaging
    encrypted_count = SecretItem.objects.filter(owner=request.user, content_encrypted__isnull=False).count()
    return render(request, 'vault/dashboard.html', {
        'items': items,
        'dek_present': bool(dek),
        'encrypted_count': encrypted_count,
    })

@login_required
def item_detail(request, pk):
    item = get_object_or_404(SecretItem, pk=pk, owner=request.user)
    dek = cache.get(f'dek:{request.session.session_key}')
    if item.content_encrypted and dek:
        try:
            item.decrypted_display = decrypt_with_dek(dek, item.content_encrypted)
        except Exception:
            item.decrypted_content = '<error decrypting>'
    else:
        item.decrypted_display = item.content or ''
    return render(request, 'vault/item_detail.html', {'item': item})


@login_required
def get_encrypted_dek(request):
    # Return the user's encrypted DEK and salt to client (base64 encoded). Only authenticated user.
    try:
        uv = request.user.vault_profile
    except Exception:
        return HttpResponseForbidden("No vault profile")
    if not uv.dek_encrypted:
        return JsonResponse({'error': 'no_dek'})
    return JsonResponse({
        'dek_encrypted': b64encode(force_bytes(uv.dek_encrypted)).decode(),
        'dek_salt': b64encode(force_bytes(uv.dek_salt)).decode(),
        'kdf_iterations': uv.dek_kdf_iterations,
    })


@login_required
def get_raw_dek(request):
    sk = request.session.session_key
    if not sk:
        request.session.save()
        sk = request.session.session_key
    dek = cache.get(f'dek:{sk}')
    if not dek:
        return JsonResponse({'error': 'no_dek_in_session'}, status=403)
    from base64 import b64encode
    return JsonResponse({'dek': b64encode(dek).decode()})


@login_required
def create_item(request):
    sk = request.session.session_key
    if not sk:
        request.session.save()
        sk = request.session.session_key
    dek_present = bool(cache.get(f'dek:{sk}'))
    if request.method == 'POST':
        form = SecretItemForm(request.POST)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.owner = request.user
            # Determine whether content is already ciphertext: we can use a form field flag `is_ciphertext`
            is_ciphertext = request.POST.get('is_ciphertext') == '1'
            sk = request.session.session_key
            if not sk:
                request.session.save()
                sk = request.session.session_key
            dek = cache.get(f'dek:{sk}')
            if is_ciphertext:
                # Content given already encrypted (base64), store as binary
                content_b64 = request.POST.get('content', '')
                try:
                    obj.content_encrypted = b64decode(content_b64)
                except Exception:
                    obj.content_encrypted = None
                obj.content = ''
            else:
                if not dek:
                    # If the user's DEK is not present in the session, we refuse to accept plaintext
                    # to prevent storing unencrypted secrets on the server.
                    messages.error(request, 'Your vault is locked; please re-login to initialize your vault before creating plaintext items.')
                    return render(request, 'vault/create_item.html', {'form': form, 'dek_present': False})
                if dek and obj.content:
                    obj.content_encrypted = encrypt_with_dek(dek, obj.content)
                    obj.content = ''
            obj.save()
            return render(request, 'vault/item_detail.html', {'item': obj})
    else:
        form = SecretItemForm()
    return render(request, 'vault/create_item.html', {'form': form, 'dek_present': dek_present})


class CustomLoginView(auth_views.LoginView):
    template_name = 'registration/login.html'

    def form_valid(self, form):
        response = super().form_valid(form)
        user = form.get_user()
        password = form.cleaned_data.get('password')
        uv, _ = UserVault.objects.get_or_create(user=user)
        if not uv.dek_encrypted:
            from os import urandom
            salt = urandom(16)
            dek = generate_dek()
            uv.dek_salt = salt
            uv.dek_encrypted = encrypt_dek_with_password(dek, password, salt)
            uv.save()
            # Migrate any existing plaintext content to encrypted content for this user
            from .crypto import encrypt_with_dek
            legacy_items = SecretItem.objects.filter(owner=user).exclude(content='')
            for li in legacy_items:
                try:
                    li.content_encrypted = encrypt_with_dek(dek, li.content)
                    li.content = ''
                    li.save()
                except Exception:
                    # If any fails just leave it plaintext for manual migration.
                    pass
        else:
            try:
                dek = decrypt_dek_with_password(uv.dek_encrypted, password, uv.dek_salt)
            except Exception:
                dek = None
        if dek:
            sk = self.request.session.session_key
            if not sk:
                self.request.session.save()
                sk = self.request.session.session_key
            cache.set(f'dek:{sk}', dek, timeout=300)
        return response


class CustomLogoutView(auth_views.LogoutView):
    template_name = 'vault/logged_out.html'

    def dispatch(self, request, *args, **kwargs):
        # Clear cached DEK for this session if any
        sk = request.session.session_key
        if sk:
            cache.delete(f'dek:{sk}')
        # Clear decrypting session flags too
        request.session.pop('show_decrypting', None)
        request.session.pop('show_decrypting_shown', None)
        return super().dispatch(request, *args, **kwargs)
