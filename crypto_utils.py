"""
crypto_utils.py
----------------
Core cryptographic functions for the Image Encryption & Sharing prototype.

Implements the Hybrid Encryption scheme discussed in the project plan:
  - AES-256-GCM  -> encrypts the actual image (fast, bulk data, built-in integrity check)
  - RSA-2048     -> encrypts the AES key individually for each recipient (secure key exchange)

NOTE ON LIBRARY CHOICE:
This sandbox environment does not have internet access to install 'pycryptodome',
so this prototype uses the 'cryptography' library instead (already available here).
The concepts, function names, and flow are written to match 1-to-1 with what you'd
write using pycryptodome, so Member 1 can port this directly if the team prefers
pycryptodome for the final submission. Both libraries implement the same underlying
AES-GCM and RSA-OAEP standards.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


# ---------------------------------------------------------------------------
# 1. RSA KEY PAIR GENERATION  (run once per user, e.g. at registration)
# ---------------------------------------------------------------------------
def generate_rsa_keypair():
    """
    Generates a new RSA-2048 key pair.
    Returns (public_key_object, private_key_object) — kept in memory for this
    prototype. In the real project, the private key must be stored encrypted
    (e.g. encrypted with the user's password) rather than in plaintext.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return public_key, private_key


# ---------------------------------------------------------------------------
# 2. AES-GCM IMAGE ENCRYPTION  (the "bulk data" layer)
# ---------------------------------------------------------------------------
def encrypt_image(image_bytes: bytes):
    """
    Encrypts raw image bytes using AES-256-GCM with a freshly generated key.
    Returns: (ciphertext, nonce, aes_key)
    Note: with AES-GCM, the authentication tag is appended to the ciphertext
    automatically — no separate SHA-256 step is needed for tamper detection.
    """
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce, standard for GCM
    ciphertext = aesgcm.encrypt(nonce, image_bytes, associated_data=None)
    return ciphertext, nonce, aes_key


def decrypt_image(ciphertext: bytes, nonce: bytes, aes_key: bytes) -> bytes:
    """
    Decrypts AES-GCM ciphertext back into the original image bytes.
    Raises an exception automatically if the data was tampered with
    (this IS your integrity check — built into GCM mode).
    """
    aesgcm = AESGCM(aes_key)
    image_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return image_bytes


# ---------------------------------------------------------------------------
# 3. RSA KEY-WRAPPING  (the "secure key exchange" layer)
# ---------------------------------------------------------------------------
def encrypt_aes_key_with_rsa(aes_key: bytes, recipient_public_key) -> bytes:
    """
    Encrypts a small AES key using the recipient's RSA public key.
    Only the matching RSA private key can recover it.
    """
    encrypted_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted_key


def decrypt_aes_key_with_rsa(encrypted_key: bytes, private_key) -> bytes:
    """
    Decrypts an RSA-wrapped AES key using the owner's RSA private key.
    """
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return aes_key


# ---------------------------------------------------------------------------
# 4. Optional: SHA-256 integrity hash (manual check, for demonstration)
# ---------------------------------------------------------------------------
import hashlib


def get_sha256_hash(data: bytes) -> str:
    """Returns a hex SHA-256 digest of the given bytes."""
    return hashlib.sha256(data).hexdigest()
