from cryptography.fernet import Fernet
from app.config import settings
import base64


def get_encryption_key() -> bytes:
    """Get or generate encryption key"""
    key = settings.encryption_key.encode()
    # Ensure key is 32 bytes for Fernet
    if len(key) != 32:
        key = key[:32].ljust(32, b'0')
    return base64.urlsafe_b64encode(key)


def encrypt_password(password: str) -> str:
    """Encrypt a password for storage"""
    if not password:
        return ""
    key = get_encryption_key()
    f = Fernet(key)
    encrypted = f.encrypt(password.encode())
    return encrypted.decode()


def decrypt_password(encrypted_password: str) -> str:
    """Decrypt a password from storage"""
    if not encrypted_password:
        return ""
    try:
        key = get_encryption_key()
        f = Fernet(key)
        decrypted = f.decrypt(encrypted_password.encode())
        return decrypted.decode()
    except Exception:
        # If decryption fails, return empty string
        return ""
