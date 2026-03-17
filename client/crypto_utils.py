def unwrap_file_encryption_key(wrapped_fek: bytes, private_key_bytes: bytes) -> bytes:
    sealed_box = SealedBox(PrivateKey(private_key_bytes))
    return sealed_box.decrypt(wrapped_fek)

def decrypt_file_bytes(ciphertext: bytes, nonce_iv: bytes, auth_tag: bytes, fek: bytes) -> bytes:
    aesgcm = AESGCM(fek)
    encrypted = ciphertext + auth_tag
    return aesgcm.decrypt(nonce_iv, encrypted, None)
import os
from nacl.public import PrivateKey, PublicKey, SealedBox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def generate_keypair():
    priv = PrivateKey.generate()
    pub = priv.public_key
    return bytes(pub), bytes(priv)


def public_key_from_private_bytes(privkey_bytes: bytes) -> bytes:
    return bytes(PrivateKey(privkey_bytes).public_key)

def derive_local_key(password: str, salt: bytes, kdf_params: dict) -> bytes:
    if kdf_params.get("name") != "scrypt":
        raise ValueError("Unsupported KDF")

    kdf = Scrypt(
        salt=salt,
        length=int(kdf_params.get("length", 32)),
        n=int(kdf_params.get("n", 2**14)),
        r=int(kdf_params.get("r", 8)),
        p=int(kdf_params.get("p", 1)),
    )
    return kdf.derive(password.encode("utf-8"))


def generate_file_encryption_key() -> bytes:
    return os.urandom(32)


def encrypt_file_bytes(plaintext: bytes, fek: bytes | None = None):
    file_encryption_key = fek or generate_file_encryption_key()
    aesgcm = AESGCM(file_encryption_key)
    nonce_iv = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce_iv, plaintext, None)

    ciphertext = encrypted[:-16]
    auth_tag = encrypted[-16:]
    return file_encryption_key, nonce_iv, ciphertext, auth_tag


def wrap_file_encryption_key(fek: bytes, recipient_public_key_bytes: bytes) -> bytes:
    sealed_box = SealedBox(PublicKey(recipient_public_key_bytes))
    return sealed_box.encrypt(fek)

def encrypt_private_key(privkey_bytes: bytes, local_key: bytes):
    aead = ChaCha20Poly1305(local_key)
    nonce = os.urandom(12)  # required length
    ciphertext = aead.encrypt(nonce, privkey_bytes, None)  # includes tag
    return nonce, ciphertext

def decrypt_private_key(ciphertext: bytes, nonce: bytes, local_key: bytes):
    aead = ChaCha20Poly1305(local_key)
    return aead.decrypt(nonce, ciphertext, None)