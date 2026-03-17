from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.utils import secure_filename
import io
from api import list_files_api, upload_file_api, download_file_api, delete_file_api
from auth import (
    register as do_register,
    login as do_login,
    logout as do_logout,
    get_private_key_bytes,
    get_auth_context,
)
from crypto_utils import encrypt_file_bytes, wrap_file_encryption_key, public_key_from_private_bytes, unwrap_file_encryption_key, decrypt_file_bytes

app = Flask(__name__)
app.secret_key = "dev-only-change-me"  # for demo; change before submission if required

@app.get("/")
def landingpage():
    logged_in = session.get("logged_in", False)
    return render_template("landingpage.html", logged_in=logged_in)

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

    import base64
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

@app.route("/home")
def home():
    if not session.get("logged_in"):
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    auth_context = get_auth_context()
    if not auth_context:
        flash("Authenticated session not available. Please login again.", "error")
        return redirect(url_for("login"))

    username = session.get("username")
    has_privkey = get_private_key_bytes() is not None
    uploaded_files = list_files_api(auth_context["username"], auth_context["password"]) or []
    uploaded_files = sorted(uploaded_files, key=lambda item: item.get("filename", "").lower())
    return render_template("home.html", username=username, has_privkey=has_privkey, uploaded_files=uploaded_files)

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

        ok = do_register(username, password)
        if ok:
            flash("Registered successfully. You can login now.", "success")
            return redirect(url_for("login"))
        else:
            # Even if server is down, your do_register may still save keystore locally (depending on your logic)
            flash("Register completed locally, but server registration may have failed (server/TLS not running).", "warning")
            return redirect(url_for("login"))

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

        flash(f"Encrypted '{safe_name}' on the client and stored ciphertext on the server.", "success")
        return redirect(url_for("home"))




if __name__ == "__main__":
    # UI server (this is your client UI). Keep it HTTP locally.
    # TLS for your project is for the *API server / reverse proxy*, not necessarily this UI.
    app.run(host="127.0.0.1", port=5001, debug=True)