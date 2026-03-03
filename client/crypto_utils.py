import os
from nacl.public import PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def generate_keypair():
    priv = PrivateKey.generate()
    pub = priv.public_key
    return bytes(pub), bytes(priv)

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

def encrypt_private_key(privkey_bytes: bytes, local_key: bytes):
    aead = ChaCha20Poly1305(local_key)
    nonce = os.urandom(12)  # required length
    ciphertext = aead.encrypt(nonce, privkey_bytes, None)  # includes tag
    return nonce, ciphertext

def decrypt_private_key(ciphertext: bytes, nonce: bytes, local_key: bytes):
    aead = ChaCha20Poly1305(local_key)
    return aead.decrypt(nonce, ciphertext, None)