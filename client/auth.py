import base64
import os
from crypto_utils import (
    generate_keypair,
    derive_local_key,
    encrypt_private_key,
    decrypt_private_key,
    public_key_from_private_bytes,
)
from keystore import save_keystore, load_keystore, DEFAULT_KDF
from api import register_api, login_api

_current_private_key = None  # bytes
_current_username = None
_current_password = None
_current_user_id = None
_current_public_key = None

def register(username, password):
    pub, priv = generate_keypair()

    salt = os.urandom(16)
    kdf_params = DEFAULT_KDF
    local_key = derive_local_key(password, salt, kdf_params)

    nonce, encrypted_priv = encrypt_private_key(priv, local_key)

    result = register_api(username, password, pub)
    ok = result is not None

    if ok:
        # Persist local keystore only when server registration succeeds.
        save_keystore(username, salt, nonce, encrypted_priv, kdf_params)
        print("Registration OK.")
    else:
        print("Registration failed. Server not reachable or returned an error.")

    return ok

def login(username, password):
    global _current_private_key, _current_username, _current_password, _current_user_id, _current_public_key

    login_result = login_api(username, password)
    if not login_result:
        print("Login failed (server).")
        return False

    bundle = load_keystore(username)
    if not bundle:
        print("No keystore found for this user.")
        return False

    salt, nonce, encrypted_priv, kdf_params = bundle
    local_key = derive_local_key(password, salt, kdf_params)

    try:
        priv = decrypt_private_key(encrypted_priv, nonce, local_key)
        _current_private_key = priv
        _current_username = username
        _current_password = password
        _current_user_id = login_result.get("user_id")

        public_key_b64 = login_result.get("public_key")
        if public_key_b64:
            _current_public_key = base64.b64decode(public_key_b64)
        else:
            _current_public_key = public_key_from_private_bytes(priv)

        print("Login OK.")
        return True
    except Exception:
        print("Wrong password or corrupted keystore.")
        return False
    
def logout():
    global _current_private_key, _current_username, _current_password, _current_user_id, _current_public_key
    _current_private_key = None
    _current_username = None
    _current_password = None
    _current_user_id = None
    _current_public_key = None
    print("Logged out (private key cleared from memory).")

def get_private_key_bytes():
    return _current_private_key


def get_auth_context():
    if not _current_private_key or not _current_username or not _current_password or not _current_user_id:
        return None

    return {
        "username": _current_username,
        "password": _current_password,
        "user_id": _current_user_id,
        "public_key": _current_public_key,
    }