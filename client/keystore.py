import json
import base64
import os

KEYSTORE_DIR = "keystores"
os.makedirs(KEYSTORE_DIR, exist_ok=True)

# Default KDF parameters used when creating/loading keystores
DEFAULT_KDF = {"name": "scrypt", "n": 16384, "r": 8, "p": 1, "length": 32}


def _get_path(username: str):
    return os.path.join(KEYSTORE_DIR, f"{username}.json")


def save_keystore(username, salt, nonce, encrypted_privkey, kdf_params):
    path = _get_path(username)

    data = {
        "kdf": kdf_params,
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "encrypted_privkey": base64.b64encode(encrypted_privkey).decode()
    }

    with open(path, "w") as f:
        json.dump(data, f)


def load_keystore(username):
    path = _get_path(username)

    if not os.path.exists(path):
        return None

    with open(path, "r") as f:
        data = json.load(f)

    salt = base64.b64decode(data["salt"])
    nonce = base64.b64decode(data["nonce"])
    encrypted_priv = base64.b64decode(data["encrypted_privkey"])
    kdf_params = data["kdf"]

    return salt, nonce, encrypted_priv, kdf_params