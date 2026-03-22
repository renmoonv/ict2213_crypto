from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from werkzeug.utils import secure_filename
import io
import os
import sys
import time
import subprocess
import requests
import mimetypes
import base64
from api import (
    list_files_api,
    upload_file_api,
    download_file_api,
    delete_file_api,
    read_file_api,
    modify_file_api,
    share_file_api,
    get_file_permissions_api,
    get_user_public_key_api,
    revoke_file_api,
)
from auth import (
    register as do_register,
    login as do_login,
    logout as do_logout,
    get_private_key_bytes,
    get_auth_context,
)
from crypto_utils import encrypt_file_bytes, wrap_file_encryption_key, public_key_from_private_bytes, unwrap_file_encryption_key, decrypt_file_bytes

app = Flask(__name__)
app.secret_key = "34fe3012ec83d4fcea670e6aef8ae804d635e4c222955f3d154ec69729e2e596"


def _api_health_check():
    try:
        response = requests.get("http://127.0.0.1:5000/api/health", timeout=1)
        return response.status_code == 200
    except requests.RequestException:
        return False


def _ensure_backend_running():
    # Enabled by default so running client app also brings up API server.
    autostart_disabled = os.getenv("CLIENT_AUTOSTART_API", "true").strip().lower() in {"0", "false", "no"}
    if autostart_disabled:
        return

    if _api_health_check():
        return

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    server_dir = os.path.join(project_root, "server")
    server_app = os.path.join(server_dir, "app.py")

    kwargs = {
        "cwd": server_dir,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "env": {**os.environ, "FLASK_DEBUG": "0"},
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS

    subprocess.Popen([sys.executable, server_app], **kwargs)

    for _ in range(20):
        if _api_health_check():
            return
        time.sleep(0.5)

    print("Backend auto-start attempted, but API health is still not ready.")

@app.route("/")
@app.route("/home")
def home():
    if not session.get("logged_in"):
        return render_template("home.html", logged_in=False)

    auth_context = get_auth_context()
    if not auth_context:
        session.clear()
        return render_template("home.html", logged_in=False)

    username = session.get("username")
    has_privkey =  get_private_key_bytes() is not None
    uploaded_files = list_files_api(auth_context["username"], auth_context["password"]) or []
    uploaded_files = sorted(uploaded_files, key=lambda item: item.get("filename", "").lower())
    return render_template("home.html", logged_in=True, username=username, has_privkey=has_privkey, uploaded_files=uploaded_files)

@app.route("/logout", methods=["POST", "GET"])
def logout():
    do_logout()
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))

# register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password required.", "error")
            return redirect(url_for("register"))

        import re
        pwd_errors = []
        if len(password) < 8:
            pwd_errors.append("at least 8 characters")
        if not re.search(r"[A-Z]", password):
            pwd_errors.append("an uppercase letter")
        if not re.search(r"[a-z]", password):
            pwd_errors.append("a lowercase letter")
        if not re.search(r"\d", password):
            pwd_errors.append("a number")
        if not re.search(r"[^A-Za-z0-9]", password):
            pwd_errors.append("a special character")
        if pwd_errors:
            flash("Password must contain: " + ", ".join(pwd_errors) + ".", "error")
            return redirect(url_for("register"))

        ok, error_msg = do_register(username, password)
        if ok:
            flash("Registered successfully. You can login now.", "success")
            return redirect(url_for("login"))
        else:
            flash(error_msg or "Registration failed.", "error")
            return redirect(url_for("register"))

    return render_template("register.html")

# login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if do_login(username, password):
            session["logged_in"] = True
            session["username"] = username
            flash("Login successful.", "success")
            return redirect(url_for("home"))
        else:
            flash("Login failed.", "error")
            return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/upload", methods=["GET", "POST"])
def upload_file():
    if not session.get("logged_in"):
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    auth_context = get_auth_context()
    if not auth_context:
        flash("Authenticated session not available. Please login again.", "error")
        return redirect(url_for("login"))

    if request.method == "GET":
        return redirect(url_for("home"))

    if request.method == "POST":
        uploaded_file = request.files.get("file")
        if uploaded_file is None:
            flash("No file part in request.", "error")
            return redirect(url_for("upload_file"))

        if uploaded_file.filename == "":
            flash("Please choose a file to upload.", "error")
            return redirect(url_for("upload_file"))

        safe_name = secure_filename(uploaded_file.filename)
        if not safe_name:
            flash("Invalid filename.", "error")
            return redirect(url_for("upload_file"))

        plaintext = uploaded_file.read()
        owner_public_key = auth_context.get("public_key") or public_key_from_private_bytes(get_private_key_bytes())
        fek, nonce_iv, ciphertext, auth_tag = encrypt_file_bytes(plaintext)
        wrapped_fek = wrap_file_encryption_key(fek, owner_public_key)

        result = upload_file_api(
            username=auth_context["username"],
            password=auth_context["password"],
            filename=safe_name,
            ciphertext=ciphertext,
            nonce_iv=nonce_iv,
            auth_tag=auth_tag,
            permissions=[
                {
                    "user_id": auth_context["user_id"],
                    "permission_type": "write",
                    "wrapped_fek": wrapped_fek,
                    "fek_version": 1,
                }
            ],
        )

        if not result:
            flash("Upload failed. Check that the API server is running and OFFLINE_DEV is disabled.", "error")
            return redirect(url_for("home"))

        flash(f"'{safe_name}' uploaded successfully.", "success")
        return redirect(url_for("home"))

# Download and decrypt file route
@app.route("/download/<int:file_id>")
def download_file(file_id):
    if not session.get("logged_in"):
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    auth_context = get_auth_context()
    if not auth_context:
        flash("Authenticated session not available. Please login again.", "error")
        return redirect(url_for("login"))

    result = download_file_api(auth_context["username"], auth_context["password"], file_id)
    if not result:
        flash("Download failed. File not found or access denied.", "error")
        return redirect(url_for("home"))

    
    ciphertext = base64.b64decode(result["ciphertext"])
    nonce_iv = base64.b64decode(result["nonce_iv"])
    auth_tag = base64.b64decode(result["auth_tag"])
    wrapped_fek = base64.b64decode(result["wrapped_fek"])
    filename = result["filename"]

    fek = unwrap_file_encryption_key(wrapped_fek, get_private_key_bytes())
    plaintext = decrypt_file_bytes(ciphertext, nonce_iv, auth_tag, fek)

    return send_file(
        io.BytesIO(plaintext),
        as_attachment=True,
        download_name=filename,
        mimetype="application/octet-stream",
    )

@app.route("/remove/<int:file_id>", methods=["POST"])
def remove_file(file_id):
    if not session.get("logged_in"):
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    auth_context = get_auth_context()
    if not auth_context:
        flash("Authenticated session not available. Please login again.", "error")
        return redirect(url_for("login"))

    result = delete_file_api(auth_context["username"], auth_context["password"], file_id)
    if not result:
        flash("Remove failed. Only the owner can delete a file, and the API server must be available.", "error")
        return redirect(url_for("home"))

    flash("File removed successfully.", "success")
    return redirect(url_for("home"))

@app.route("/file_permissions/<int:file_id>", methods=["GET"])
def file_permissions(file_id):
    if not session.get("logged_in"):
        return jsonify({"error": "Please login first."}), 401

    auth_context = get_auth_context()
    if not auth_context:
        return jsonify({"error": "Authenticated session not available. Please login again."}), 401

    perms = get_file_permissions_api(auth_context["username"], auth_context["password"], file_id)
    if perms is None:
        return jsonify({"error": "Failed to fetch permissions"}), 500

    return jsonify(perms), 200

@app.route("/share/<int:file_id>", methods=["POST"])
def share_file(file_id):
    if not session.get("logged_in"):
        return jsonify({"error": "Please login first."}), 401

    auth_context = get_auth_context()
    if not auth_context:
        return jsonify({"error": "Authenticated session not available. Please login again."}), 401

    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    target_username = data.get("target_username")
    permission_type = data.get("permission_type")

    if not target_username or permission_type not in ("read", "write"):
        return jsonify({"error": "target_username and permission_type (read|write) required"}), 400

    # resolve target user
    lookup_resp = requests.get(
        f"http://127.0.0.1:5000/api/users/lookup?username={target_username}",
        headers={
            "X-Username": auth_context["username"],
            "X-Password": auth_context["password"],
        },
        timeout=10,
        verify=False,
    )
    if lookup_resp.status_code != 200:
        return jsonify({"error": "Target user not found"}), lookup_resp.status_code

    target_info = lookup_resp.json()
    target_user_id = target_info.get("user_id")
    target_public_key_b64 = target_info.get("public_key")

    if not target_user_id or not target_public_key_b64:
        return jsonify({"error": "Failed to get target user public key"}), 500

    target_public_key_bytes = base64.b64decode(target_public_key_b64)

    # get this file ciphertext and owner wrapped key via download endpoint
    file_data = download_file_api(auth_context["username"], auth_context["password"], file_id)
    if not file_data:
        return jsonify({"error": "Cannot access file or share not allowed"}), 403

    wrapped_fek_b64 = file_data.get("wrapped_fek")
    if not wrapped_fek_b64:
        return jsonify({"error": "Owner wrapped key not found"}), 500

    wrapped_fek = base64.b64decode(wrapped_fek_b64)

    # decrypt FEK with owner private key and re-wrap for target user
    try:
        fek = unwrap_file_encryption_key(wrapped_fek, get_private_key_bytes())
    except Exception as e:
        return jsonify({"error": f"Failed to unwrap FEK: {str(e)}"}), 500

    try:
        new_wrapped_fek = wrap_file_encryption_key(fek, target_public_key_bytes)
    except Exception as e:
        return jsonify({"error": f"Failed to wrap FEK for target user: {str(e)}"}), 500

    new_wrapped_fek_b64 = base64.b64encode(new_wrapped_fek).decode("ascii")

    share_resp = share_file_api(
        auth_context["username"],
        auth_context["password"],
        file_id,
        target_user_id,
        permission_type,
        new_wrapped_fek_b64,
        fek_version=file_data.get("fek_version"),
    )

    if not share_resp:
        return jsonify({"error": "Share request failed."}), 500

    return jsonify({"message": "File shared successfully", "target_user_id": target_user_id}), 200

@app.route("/revoke/<int:file_id>", methods=["POST"])
def revoke_user(file_id):
    if not session.get("logged_in"):
        return jsonify({"error": "Please login first."}), 401

    auth_context = get_auth_context()
    if not auth_context:
        return jsonify({"error": "Authenticated session not available. Please login again."}), 401

    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    target_username = data.get("target_username")
    if not target_username:
        return jsonify({"error": "target_username required"}), 400

    # resolve user to revoke
    lookup_resp = requests.get(
        f"http://127.0.0.1:5000/api/users/lookup?username={target_username}",
        headers={
            "X-Username": auth_context["username"],
            "X-Password": auth_context["password"],
        },
        timeout=10,
        verify=False,
    )
    if lookup_resp.status_code != 200:
        result = lookup_resp.json() if lookup_resp.content else {}
        return jsonify({"error": result.get("error", "Target user not found")}), lookup_resp.status_code

    target_info = lookup_resp.json()
    revoked_user_id = target_info.get("user_id")
    if not revoked_user_id:
        return jsonify({"error": "Failed to resolve target user"}), 500

    # download file and decrypt plaintext with owner key
    file_data = download_file_api(auth_context["username"], auth_context["password"], file_id)
    if not file_data:
        return jsonify({"error": "Cannot access file or share not allowed"}), 403

    wrapped_fek_b64 = file_data.get("wrapped_fek")
    if not wrapped_fek_b64:
        return jsonify({"error": "Owner wrapped key not found"}), 500

    try:
        owner_fek = unwrap_file_encryption_key(base64.b64decode(wrapped_fek_b64), get_private_key_bytes())
    except Exception as e:
        return jsonify({"error": f"Failed to unwrap owner FEK: {str(e)}"}), 500

    try:
        ciphertext = base64.b64decode(file_data.get("ciphertext"))
        nonce_iv = base64.b64decode(file_data.get("nonce_iv"))
        auth_tag = base64.b64decode(file_data.get("auth_tag"))
        plaintext = decrypt_file_bytes(ciphertext, nonce_iv, auth_tag, owner_fek)
    except Exception as e:
        return jsonify({"error": f"Failed to decrypt file for rekey: {str(e)}"}), 500

    # re-encrypt with a new FEK
    new_fek, new_nonce_iv, new_ciphertext, new_auth_tag = encrypt_file_bytes(plaintext)

    # get current sharing permissions and publicly wrap new FEK for remaining users (including owner)
    perms = get_file_permissions_api(auth_context["username"], auth_context["password"], file_id)
    if perms is None:
        return jsonify({"error": "Failed to fetch file permissions"}), 500

    remaining_users = []
    for perm in perms:
        uid = perm.get("user_id")
        if uid == revoked_user_id:
            continue

        if uid == auth_context.get("user_id"):
            target_public_key_bytes = auth_context.get("public_key")
        else:
            user_key = get_user_public_key_api(auth_context["username"], auth_context["password"], uid)
            if not user_key:
                return jsonify({"error": f"Failed to fetch public key for user {uid}"}), 500

            public_key_b64 = user_key.get("public_key")
            if not public_key_b64:
                return jsonify({"error": f"Public key missing for user {uid}"}), 500

            try:
                target_public_key_bytes = base64.b64decode(public_key_b64)
            except Exception as e:
                return jsonify({"error": f"Failed to decode public key for user {uid}: {str(e)}"}), 500

        if not target_public_key_bytes:
            return jsonify({"error": f"Public key missing for user {uid}"}), 500

        wrapped = wrap_file_encryption_key(new_fek, target_public_key_bytes)
        remaining_users.append({
            "user_id": uid,
            "wrapped_fek": base64.b64encode(wrapped).decode("ascii"),
        })

    revoke_resp = revoke_file_api(
        auth_context["username"],
        auth_context["password"],
        file_id,
        revoked_user_id,
        base64.b64encode(new_ciphertext).decode("ascii"),
        base64.b64encode(new_nonce_iv).decode("ascii"),
        base64.b64encode(new_auth_tag).decode("ascii"),
        remaining_users,
        fek_version=file_data.get("fek_version", 1) + 1,
    )

    if not revoke_resp:
        return jsonify({"error": "Revoke request failed."}), 500

    return jsonify({"message": "User revoked and file rekeyed successfully", "revoked_user_id": revoked_user_id}), 200


@app.route("/api/files/<int:file_id>/content", methods=["GET"])
def get_file_content(file_id):
    if not session.get("logged_in"):
        return jsonify({"error": "Not logged in"}), 401

    try:
        plaintext, fek, perm_type = read_file(file_id, get_private_key_bytes())
        session[f"fek_{file_id}"] = base64.b64encode(fek).decode()

        # handle binary files 
        try:
            content = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            content = None

        return jsonify({
            "content": content,
            "permission_type": perm_type,
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/api/files/<int:file_id>/content", methods=["PUT"])
def put_file_content(file_id):
    if not session.get("logged_in"):
        return jsonify({"error": "Not logged in"}), 401

    fek_b64 = session.get(f"fek_{file_id}")
    if not fek_b64:
        return jsonify({"error": "Re-open the file first"}), 400
    
    body = request.get_json()
    is_binary = body.get("is_binary", False)

    if is_binary:
        new_content = base64.b64decode(body.get("content", ""))
    else:
        new_content = body.get("content", "").encode("utf-8")

    try:
        modify_file(file_id, new_content, base64.b64decode(fek_b64))
        return jsonify({"message": "File updated"})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

def read_file(file_id, private_key_bytes):
    auth_context = get_auth_context()
    if not auth_context:
        flash("Authenticated session not available. Please login again.", "error")
        return redirect(url_for("login"))

    result = read_file_api(auth_context["username"], auth_context["password"], file_id)
    if not result:
        raise RuntimeError("Failed to read file")

    ciphertext = base64.b64decode(result["ciphertext"])
    nonce_iv = base64.b64decode(result["nonce_iv"])
    auth_tag = base64.b64decode(result["auth_tag"])
    wrapped_fek = base64.b64decode(result["wrapped_fek"])
    perm_type = result["permission_type"] 

    fek = unwrap_file_encryption_key(wrapped_fek, private_key_bytes)

    plaintext = decrypt_file_bytes(ciphertext, nonce_iv, auth_tag, fek)
    return plaintext, fek, perm_type


def modify_file(file_id, new_content_bytes, fek):
    auth_context = get_auth_context()
    if not auth_context:
        raise RuntimeError("No auth context available")

    # re-encrypt with same FEK, new IV
    _, new_nonce_iv, new_ciphertext, new_auth_tag = encrypt_file_bytes(new_content_bytes, fek)

    payload = {
        "ciphertext": base64.b64encode(new_ciphertext).decode(),
        "nonce_iv":   base64.b64encode(new_nonce_iv).decode(),
        "auth_tag":   base64.b64encode(new_auth_tag).decode()
    }

    result = modify_file_api(  
        auth_context["username"],
        auth_context["password"],
        file_id,
        payload
    )
    if not result:
        raise RuntimeError("Failed to update file")
    return result

if __name__ == "__main__":
    _ensure_backend_running()
    # UI server (this is your client UI). Keep it HTTP locally.
    # TLS for your project is for the *API server / reverse proxy*, not necessarily this UI.
    app.run(host="127.0.0.1", port=5001, debug=True)