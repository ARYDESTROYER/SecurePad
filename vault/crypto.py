import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_dek():
    return base64.urlsafe_b64encode(os.urandom(32))

def derive_key_from_password(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_dek_with_password(dek: bytes, password: str, salt: bytes) -> bytes:
    key = derive_key_from_password(password, salt)
    f = Fernet(key)
    return f.encrypt(dek)

def decrypt_dek_with_password(encrypted_dek: bytes, password: str, salt: bytes) -> bytes:
    key = derive_key_from_password(password, salt)
    f = Fernet(key)
    return f.decrypt(encrypted_dek)

def encrypt_with_dek(dek: bytes, plaintext: str) -> bytes:
    f = Fernet(dek)
    return f.encrypt(plaintext.encode())

def decrypt_with_dek(dek: bytes, ciphertext: bytes) -> str:
    # Try Fernet first
    try:
        f = Fernet(dek)
        return f.decrypt(ciphertext).decode()
    except Exception:
        pass
    # Fall back to AES-GCM: expected format: iv (12 bytes) + ciphertext + tag (16 bytes)
    try:
        iv = ciphertext[:12]
        ct = ciphertext[12:]
        key = base64.urlsafe_b64decode(dek)
        aesgcm = AESGCM(key)
        pt = aesgcm.decrypt(iv, ct, None)
        return pt.decode()
    except Exception:
        raise

def encrypt_with_dek_aes(dek: bytes, plaintext: str) -> bytes:
    key = base64.urlsafe_b64decode(dek)
    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    ct = aesgcm.encrypt(iv, plaintext.encode(), None)
    return iv + ct
