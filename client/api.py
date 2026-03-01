import requests

BASE_URL = "https://localhost:8443"
OFFLINE_DEV = True  # set False when server is ready

def register_api(username, password, pubkey_bytes):
    if OFFLINE_DEV:
        return True
    payload = {"username": username, "password": password, "pub_key": pubkey_bytes.hex()}
    r = requests.post(f"{BASE_URL}/register", json=payload, verify=False, timeout=5)
    return r.status_code == 200

def login_api(username, password):
    if OFFLINE_DEV:
        return True
    payload = {"username": username, "password": password}
    r = requests.post(f"{BASE_URL}/login", json=payload, verify=False, timeout=5)
    return r.status_code == 200