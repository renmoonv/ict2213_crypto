import os
import sys
import json
import base64
from pathlib import Path

DEFAULT_KDF = {
    "name": "scrypt",
    "n": 16384,
    "r": 8,
    "p": 1,
    "dklen": 32,
}


def _get_keystore_dir() -> Path:
    if os.name == "nt":
        base = os.getenv("LOCALAPPDATA")
        if not base:
            base = str(Path.home() / "AppData" / "Local")
        path = Path(base) / "ICT2213_Crypto" / "keystores"
    elif sys.platform == "darwin":
        path = Path.home() / "Library" / "Application Support" / "ICT2213_Crypto" / "keystores"
    else:
        base = os.getenv("XDG_DATA_HOME")
        if base:
            path = Path(base) / "ICT2213_Crypto" / "keystores"
        else:
            path = Path.home() / ".local" / "share" / "ICT2213_Crypto" / "keystores"

    path.mkdir(parents=True, exist_ok=True)
    return path


def _keystore_path(username: str) -> Path:
    safe_username = "".join(c for c in username if c.isalnum() or c in ("-", "_", "."))
    return _get_keystore_dir() / f"{safe_username}.json"


def save_keystore(username, salt, nonce, encrypted_priv, kdf_params):
    path = _keystore_path(username)

    payload = {
        "username": username,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "encrypted_private_key": base64.b64encode(encrypted_priv).decode("ascii"),
        "kdf_params": kdf_params,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"[DEBUG] Saving keystore to: {path}")
    return str(path)


def load_keystore(username):
    path = _keystore_path(username)
    print(f"[DEBUG] Loading keystore from: {path}")

    if not path.exists():
        return None

    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    salt = base64.b64decode(payload["salt"])
    nonce = base64.b64decode(payload["nonce"])
    encrypted_priv = base64.b64decode(payload["encrypted_private_key"])
    kdf_params = payload.get("kdf_params", DEFAULT_KDF)

    return salt, nonce, encrypted_priv, kdf_params


def keystore_exists(username):
    return _keystore_path(username).exists()