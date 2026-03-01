import os
from crypto_utils import generate_keypair, derive_local_key, encrypt_private_key, decrypt_private_key
from keystore import save_keystore, load_keystore, DEFAULT_KDF
from api import register_api, login_api

_current_private_key = None  # bytes

def register(username, password):
    pub, priv = generate_keypair()

    salt = os.urandom(16)
    kdf_params = DEFAULT_KDF
    local_key = derive_local_key(password, salt, kdf_params)

    nonce, encrypted_priv = encrypt_private_key(priv, local_key)

    # Always save locally first
    save_keystore(salt, nonce, encrypted_priv, kdf_params)

    ok = register_api(username, password, pub)
    if ok:
        print("Registration OK (local keystore saved).")
        return True
    print("Server register failed, but local keystore saved.")
    return False

def login(username, password):
    global _current_private_key

    ok = login_api(username, password)
    if not ok:
        print("Login failed (server).")
        return False

    bundle = load_keystore()
    if not bundle:
        print("No keystore.json found. Register first.")
        return False

    salt, nonce, encrypted_priv, kdf_params = bundle
    local_key = derive_local_key(password, salt, kdf_params)

    try:
        priv = decrypt_private_key(encrypted_priv, nonce, local_key)
        _current_private_key = priv
        print("Login OK (private key decrypted into memory).")
        return True
    except Exception:
        print("Login failed: could not decrypt private key (wrong password or tampered keystore).")
        _current_private_key = None
        return False

def logout():
    global _current_private_key
    _current_private_key = None
    print("Logged out (private key cleared from memory).")

def get_private_key_bytes():
    return _current_private_key