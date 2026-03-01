import json
import base64
import os

KEYSTORE_FILE = "keystore.json"

DEFAULT_KDF = {
    "name": "scrypt",
    "n": 2**14,
    "r": 8,
    "p": 1,
    "length": 32
}

def save_keystore(salt, nonce, encrypted_privkey, kdf_params=None):
    if kdf_params is None:
        kdf_params = DEFAULT_KDF

    data = {
        "kdf": kdf_params,
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "encrypted_privkey": base64.b64encode(encrypted_privkey).decode()
    }
    with open(KEYSTORE_FILE, "w") as f:
        json.dump(data, f)


def load_keystore():
    if not os.path.exists(KEYSTORE_FILE):
        return None

    with open(KEYSTORE_FILE, "r") as f:
        data = json.load(f)

    salt = base64.b64decode(data["salt"])
    nonce = base64.b64decode(data["nonce"])
    encrypted_priv = base64.b64decode(data["encrypted_privkey"])
    kdf_params = data.get("kdf", DEFAULT_KDF)

    return salt, nonce, encrypted_priv, kdf_params