"""
FlexEdgeAdmin — Field-level encryption for sensitive data.

Uses Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256).
The encryption key is stored as a binary key file with a magic header,
generated once during first setup and never regenerated.

Without the key file, encrypted database fields are irrecoverable (by design).
Backup strategy: DB file + encryption key file = full restore.
"""

import hashlib
import os
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

# Binary key file format: MAGIC (4 bytes) + VERSION (1 byte) + Fernet key (44 bytes)
MAGIC = b"FXEK"
VERSION = b"\x01"
HEADER_LEN = len(MAGIC) + len(VERSION)

KEY_FILE = os.environ.get(
    "ENCRYPTION_KEY_FILE",
    os.path.join(os.path.dirname(__file__), "..", "config", "encryption.key"),
)


class EncryptionKeyError(Exception):
    """Raised when the encryption key file is missing, invalid, or corrupted."""


def generate_key_file(path: str = None) -> bytes:
    """Generate a new Fernet key and write it as a compiled binary key file.

    The file is written with 0600 permissions (owner read/write only).
    Returns the raw Fernet key bytes.
    """
    path = path or KEY_FILE
    key = Fernet.generate_key()

    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "wb") as f:
        f.write(MAGIC + VERSION + key)

    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows or restricted filesystem

    # Clear the cached Fernet instance so it reloads the new key
    _get_fernet_cached.cache_clear()

    return key


def load_key(path: str = None) -> bytes:
    """Load and validate the Fernet key from the binary key file.

    Raises EncryptionKeyError if the file is missing, too short, or has
    an invalid magic header or unsupported version.
    """
    path = path or KEY_FILE

    if not os.path.isfile(path):
        raise EncryptionKeyError(
            f"Encryption key file not found: {path}\n"
            f"Run the setup wizard or deploy.sh to generate it."
        )

    with open(path, "rb") as f:
        data = f.read()

    if len(data) < HEADER_LEN + 44:
        raise EncryptionKeyError("Encryption key file is too short or corrupted.")

    if data[:4] != MAGIC:
        raise EncryptionKeyError(
            "Invalid encryption key file format. "
            "Expected FXEK header — file may be corrupted or not a FlexEdgeAdmin key."
        )

    if data[4:5] != VERSION:
        raise EncryptionKeyError(
            f"Unsupported key file version: {data[4]}. "
            f"This build supports version {VERSION[0]}."
        )

    return data[HEADER_LEN : HEADER_LEN + 44]


@lru_cache(maxsize=1)
def _get_fernet_cached() -> Fernet:
    """Return a cached Fernet instance. Loaded once per process."""
    return Fernet(load_key())


def get_fernet(path: str = None) -> Fernet:
    """Return a Fernet instance for encrypt/decrypt operations.

    Uses a per-process cache for the default key path.
    """
    if path is None:
        return _get_fernet_cached()
    return Fernet(load_key(path))


def encrypt_value(plaintext: str) -> str:
    """Encrypt a plaintext string. Returns a Fernet token as a UTF-8 string."""
    f = get_fernet()
    return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_value(token: str) -> str:
    """Decrypt a Fernet token back to a plaintext string.

    Raises EncryptionKeyError if decryption fails (wrong key or corrupted data).
    """
    f = get_fernet()
    try:
        return f.decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        raise EncryptionKeyError(
            "Failed to decrypt value — the encryption key may have changed "
            "or the data is corrupted."
        )


def hash_value(plaintext: str) -> str:
    """SHA-256 hash of a plaintext string, for deduplication without decryption."""
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def key_file_exists(path: str = None) -> bool:
    """Check whether the encryption key file exists."""
    return os.path.isfile(path or KEY_FILE)
