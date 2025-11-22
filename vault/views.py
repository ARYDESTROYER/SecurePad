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
from django.shortcuts import redirect
from django.utils.encoding import force_bytes
from base64 import b64encode, b64decode
import base64
import re
from .forms import SecretItemForm
from .crypto import encrypt_with_dek
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import ensure_csrf_cookie


_BASE64_RE = re.compile(r'^[A-Za-z0-9+/=_-]+$')


def _maybe_decode_base64_bytes(value: str):
    if not value:
        return None
    stripped = value.strip()
    if len(stripped) < 16:
        return None
    if not _BASE64_RE.match(stripped):
        return None
    try:
        decoded = b64decode(stripped, validate=True)
        if len(decoded) >= 16:
            return decoded
    except Exception:
        pass
    try:
        pad = '=' * ((4 - len(stripped) % 4) % 4)
        decoded = base64.urlsafe_b64decode(stripped + pad)
        if len(decoded) >= 16:
            return decoded
    except Exception:
        return None
    return None


def _ciphertext_context(content_encrypted, content_text):
    """Return candidates for decryption, canonical base64, and warning flag."""
    candidates = []
    canonical_b64 = None
    warn = False
    if content_encrypted:
        binary = bytes(content_encrypted)
        candidates.append(binary)
        canonical_b64 = b64encode(binary).decode()
    text_value = (content_text or '').strip()
    decoded = _maybe_decode_base64_bytes(text_value)
    if decoded:
        warn = True
        ascii_bytes = text_value.encode()
        if ascii_bytes and ascii_bytes not in candidates:
            candidates.append(ascii_bytes)
        if decoded not in candidates:
            candidates.append(decoded)
        canonical_b64 = b64encode(decoded).decode()
    return candidates, canonical_b64, warn

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
        candidates, canonical_b64, warn = _ciphertext_context(item.content_encrypted, item.content)
        item.warn_client_ciphertext = warn
        decrypted = None
        if dek and candidates:
            for candidate in candidates:
                try:
                    # candidate may already be ciphertext bytes or ascii base64; try decode when necessary
                    if isinstance(candidate, str):
                        candidate_bytes = b64decode(candidate)
                    else:
                        candidate_bytes = candidate
                    decrypted = decrypt_with_dek(dek, candidate_bytes)
                    break
                except Exception:
                    continue
        if decrypted is not None:
            item.decrypted_display = decrypted
        else:
            # If no DEK or decrypt failed, fall back to stored plaintext (which may still be ciphertext-looking)
            item.decrypted_display = item.content or ''
        item.canonical_ciphertext_b64 = canonical_b64
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
    candidates, canonical_b64, warn = _ciphertext_context(item.content_encrypted, item.content)
    encrypted_b64 = canonical_b64
    decrypted = None
    if dek and candidates:
        for candidate in candidates:
            try:
                if isinstance(candidate, str):
                    candidate_bytes = b64decode(candidate)
                else:
                    candidate_bytes = candidate
                decrypted = decrypt_with_dek(dek, candidate_bytes)
                break
            except Exception:
                continue
    if decrypted is not None:
        item.decrypted_display = decrypted
    else:
        item.decrypted_display = item.content or ''
    return render(request, 'vault/item_detail.html', {'item': item, 'encrypted_b64': encrypted_b64, 'dek_present': bool(dek)})


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
    # `dek` is already a urlsafe base64-encoded bytes string (from generate_dek)
    # Return it as a string without additional base64-encoding so clients get the original URL-safe base64 key.
    try:
        # If dek is a bytes-like object containing ascii base64 text, decode it to str.
        dek_str = dek.decode()
    except Exception:
        # Fallback to b64encode if something unexpected is stored
        from base64 import b64encode
        dek_str = b64encode(dek).decode()
    return JsonResponse({'dek': dek_str})


@require_POST
@ensure_csrf_cookie
@login_required
def reauth_vault(request):
    """Re-authenticate to fetch/decrypt and cache the user's DEK for this session.

    Expects: POST with 'password'. Returns JSON with status and possibly message.
    """
    password = request.POST.get('password')
    if not password:
        return JsonResponse({'error': 'missing_password'}, status=400)
    try:
        uv = request.user.vault_profile
    except Exception:
        return JsonResponse({'error': 'no_vault_profile'}, status=403)
    if not uv.dek_encrypted:
        return JsonResponse({'error': 'no_dek'}, status=403)
    try:
        dek = decrypt_dek_with_password(uv.dek_encrypted, password, uv.dek_salt)
    except Exception:
        return JsonResponse({'error': 'invalid_password'}, status=403)
    # Cache decrypted dek for this session
    sk = request.session.session_key
    if not sk:
        request.session.save()
        sk = request.session.session_key
    cache.set(f'dek:{sk}', dek, timeout=300)
    # show the decrypting message once so UI gives feedback
    request.session['show_decrypting'] = True
    return JsonResponse({'status': 'ok'})


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
            submission_id = request.POST.get('submission_id') or ''
            submission_key = None
            inflight_claimed = False
            if submission_id:
                submission_key = f'submission:{submission_id}'
                cached_value = cache.get(submission_key)
                if isinstance(cached_value, int):
                    return redirect('vault:item_detail', pk=cached_value)
                if cached_value == 'inflight':
                    messages.info(request, 'Previous submission is still processing. Please wait a moment and refresh.')
                    return redirect('vault:dashboard')
                inflight_claimed = cache.add(submission_key, 'inflight', timeout=60)

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
                    if submission_key and inflight_claimed:
                        cache.delete(submission_key)
                    messages.error(request, 'Your vault is locked; please re-login to initialize your vault before creating plaintext items.')
                    return render(request, 'vault/create_item.html', {'form': form, 'dek_present': False})
                if dek and obj.content:
                    obj.content_encrypted = encrypt_with_dek(dek, obj.content)
                    obj.content = ''
            # Check for submission idempotency token to avoid duplicate POSTs
            if submission_key and not inflight_claimed:
                existing_pk = cache.get(submission_key)
                if isinstance(existing_pk, int):
                    return redirect('vault:item_detail', pk=existing_pk)

            # Prevent duplicate creation: look for an existing item with the same owner/title and encryption
            existing = None
            if obj.content_encrypted:
                existing = SecretItem.objects.filter(owner=request.user, title=obj.title, content_encrypted=obj.content_encrypted).first()
            else:
                existing = SecretItem.objects.filter(owner=request.user, title=obj.title, content=obj.content).first()
            if existing:
                if submission_key:
                    cache.set(submission_key, existing.pk, timeout=60)
                # Redirect to existing item detail
                return redirect('vault:item_detail', pk=existing.pk)
            obj.save()
            if submission_key:
                cache.set(submission_key, obj.pk, timeout=60)
            return redirect('vault:item_detail', pk=obj.pk)
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
