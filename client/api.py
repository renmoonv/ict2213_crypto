import base64
import os
import time

import requests

BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:5000")
OFFLINE_DEV = os.getenv("OFFLINE_DEV", "false").strip().lower() in {"1", "true", "yes"}
REQUEST_RETRIES = int(os.getenv("API_REQUEST_RETRIES", "5"))
RETRY_DELAY_SECONDS = float(os.getenv("API_RETRY_DELAY_SECONDS", "1"))


def _auth_headers(username, password):
    return {
        "X-Username": username,
        "X-Password": password,
    }


def _request(method, path, **kwargs):
    if OFFLINE_DEV:
        return None

    for attempt in range(1, REQUEST_RETRIES + 1):
        try:
            response = requests.request(
                method,
                f"{BASE_URL}{path}",
                verify=False,
                timeout=10,
                **kwargs,
            )
            if response.ok:
                return response.json()

            # Retry transient server startup failures, return None for final failure.
            if response.status_code >= 500 and attempt < REQUEST_RETRIES:
                time.sleep(RETRY_DELAY_SECONDS)
                continue
            return None
        except requests.RequestException:
            if attempt < REQUEST_RETRIES:
                time.sleep(RETRY_DELAY_SECONDS)
                continue
            return None

    return None


def register_api(username, password, pubkey_bytes):
    payload = {
        "username": username,
        "password": password,
        "public_key": base64.b64encode(pubkey_bytes).decode("ascii"),
    }
    return _request("POST", "/api/register", json=payload)


def login_api(username, password):
    payload = {"username": username, "password": password}
    return _request("POST", "/api/login", json=payload)


def upload_file_api(username, password, filename, ciphertext, nonce_iv, auth_tag, permissions):
    payload = {
        "filename": filename,
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "nonce_iv": base64.b64encode(nonce_iv).decode("ascii"),
        "auth_tag": base64.b64encode(auth_tag).decode("ascii"),
        "permissions": [
            {
                "user_id": permission["user_id"],
                "permission_type": permission["permission_type"],
                "wrapped_fek": base64.b64encode(permission["wrapped_fek"]).decode("ascii"),
                "fek_version": permission.get("fek_version", 1),
            }
            for permission in permissions
        ],
    }
    return _request(
        "POST",
        "/api/files",
        json=payload,
        headers=_auth_headers(username, password),
    )

def list_files_api(username, password):
    return _request("GET", "/api/files", headers=_auth_headers(username, password))

def download_file_api(username, password, file_id):
    return _request(
        "GET",
        f"/api/files/{file_id}",
        headers=_auth_headers(username, password),
    )

def delete_file_api(username, password, file_id):
    return _request(
        "DELETE",
        f"/api/files/{file_id}",
        headers=_auth_headers(username, password),
    )

def read_file_api(username, password, file_id):
    return _request(
        "GET",
        f"/api/files/{file_id}",
        headers=_auth_headers(username, password),
    )

def modify_file_api(username, password, file_id, payload):
    return _request(
        "PUT",
        f"/api/files/{file_id}",
        headers=_auth_headers(username, password),
        json=payload
    )