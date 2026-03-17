from flask import Flask, request, jsonify
from config import Config
from models import db, User, File, FilePermission, WrappedKey
from functools import wraps
import base64
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

ph = PasswordHasher()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    # ---------- AUTH HELPER ----------

    def require_auth(f):
        """
        Reads credentials from either:
          - HTTP headers:  X-Username  +  X-Password
          - JSON body:     username    +  password
        Verifies the plaintext password against the Argon2id hash stored in DB.
        On success, sets request.current_user to the User ORM object.
        """
        @wraps(f)
        def wrapper(*args, **kwargs):
            username = request.headers.get("X-Username")
            password = request.headers.get("X-Password")

            if not username or not password:
                data = request.get_json(silent=True) or {}
                username = username or data.get("username")
                password = password or data.get("password")

            if not username or not password:
                return jsonify({"error": "Missing credentials"}), 401

            user = User.query.filter_by(username=username).first()
            if not user:
                return jsonify({"error": "Invalid username or password"}), 401

            try:
                ph.verify(user.password_hash, password)
            except (VerifyMismatchError, VerificationError, InvalidHashError):
                return jsonify({"error": "Invalid username or password"}), 401

            request.current_user = user
            return f(*args, **kwargs)

        return wrapper

    # ---------- HELPERS ----------

    def b64decode_field(value, field_name):
        try:
            return base64.b64decode(value)
        except Exception:
            raise ValueError(f"{field_name} must be valid base64")

    def b64encode_bytes(value):
        return base64.b64encode(value).decode("ascii")

    def get_permission(file_id, user_id):
        return FilePermission.query.filter_by(file_id=file_id, user_id=user_id).first()

    def can_read(permission):
        return permission is not None and permission.permission_type in ("read", "write")

    def can_write(permission):
        return permission is not None and permission.permission_type == "write"

    # ---------- AUTH ENDPOINTS ----------

    @app.route("/api/register", methods=["POST"])
    def register():
        """
        Register a new user.

        Request JSON:
            username    (str)  - unique username
            password    (str)  - plaintext password; server hashes with Argon2id
            public_key  (str)  - X25519 public key, Base64-encoded

        Response 201:
            { "message": "User registered", "user_id": <int> }
        """
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        username   = data.get("username")
        password   = data.get("password")
        public_key = data.get("public_key")

        if not username or not password or not public_key:
            return jsonify({"error": "username, password, public_key required"}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({"error": "Username already taken"}), 409

        password_hash = ph.hash(password)

        user = User(
            username=username,
            password_hash=password_hash,
            public_key=public_key,
        )
        db.session.add(user)
        db.session.commit()

        return jsonify({"message": "User registered", "user_id": user.user_id}), 201

    @app.route("/api/login", methods=["POST"])
    def login():
        """
        Authenticate a user.

        Request JSON:
            username  (str) - username
            password  (str) - plaintext password

        Response 200:
            { "message": "Login OK", "user_id": <int>, "public_key": <str> }
        """
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "username and password required"}), 400

        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"error": "Invalid username or password"}), 401

        try:
            ph.verify(user.password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return jsonify({"error": "Invalid username or password"}), 401

        return jsonify({
            "message": "Login OK",
            "user_id": user.user_id,
            "public_key": user.public_key,
        }), 200

    # ---------- USER LOOKUP ENDPOINTS ----------

    @app.route("/api/users/<int:user_id>/public-key", methods=["GET"])
    @require_auth
    def get_public_key_by_id(user_id):
        """
        Fetch a user's public key by user_id.
        Used by the owner when sharing a file — owner needs recipient's public key
        to wrap the FEK client-side.

        Response 200:
            { "user_id": <int>, "username": <str>, "public_key": <str> }
        """
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404

        return jsonify({
            "user_id": user.user_id,
            "username": user.username,
            "public_key": user.public_key,
        }), 200

    @app.route("/api/users/lookup", methods=["GET"])
    @require_auth
    def lookup_user():
        """
        Look up a user's public key by username.
        Query param: ?username=<str>

        Used by the sharing UI so the owner can type a username and get back
        the user_id + public key to wrap the FEK for.

        Response 200:
            { "user_id": <int>, "username": <str>, "public_key": <str> }
        """
        username = request.args.get("username")
        if not username:
            return jsonify({"error": "username query param required"}), 400

        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"error": "User not found"}), 404

        return jsonify({
            "user_id": user.user_id,
            "username": user.username,
            "public_key": user.public_key,
        }), 200

    # ---------- FILE ENDPOINTS ----------

    @app.route("/api/files", methods=["GET"])
    @require_auth
    def list_files():
        """
        List all files the authenticated user has access to (owned or shared).

        Response 200:
            [
              {
                "file_id": <int>,
                "filename": <str>,
                "owner_id": <int>,
                "is_owner": <bool>,
                "permission_type": "read" | "write",
                "fek_version": <int>
              },
              ...
            ]
        """
        u = request.current_user

        perms = FilePermission.query.filter_by(user_id=u.user_id).all()

        result = []
        for perm in perms:
            file_obj = File.query.get(perm.file_id)
            if not file_obj:
                continue

            wrapped_key = WrappedKey.query.filter_by(
                file_id=file_obj.file_id,
                user_id=u.user_id,
            ).first()

            result.append({
                "file_id": file_obj.file_id,
                "filename": file_obj.filename,
                "owner_id": file_obj.owner_id,
                "is_owner": file_obj.owner_id == u.user_id,
                "permission_type": perm.permission_type,
                "fek_version": wrapped_key.fek_version if wrapped_key else None,
            })

        return jsonify(result), 200

    @app.route("/api/files", methods=["POST"])
    @require_auth
    def upload_file():
        """
        Upload a new encrypted file.

        The client encrypts the file with AES-256-GCM before sending.
        The client also wraps the FEK with each authorised user's public key
        (sealed box) and sends those wrapped keys here.
        The owner MUST be included in the permissions list.

        Request JSON:
            filename     (str)  - original filename
            ciphertext   (str)  - base64-encoded AES-256-GCM ciphertext
            nonce_iv     (str)  - base64-encoded 12-byte nonce
            auth_tag     (str)  - base64-encoded 16-byte GCM auth tag
            permissions  (list) - [
                {
                  "user_id":         <int>,
                  "permission_type": "read" | "write",
                  "wrapped_fek":     <base64 str>,   # FEK sealed with user's public key
                  "fek_version":     <int>            # optional, default 1
                },
                ...
              ]

        Response 201:
            { "message": "File uploaded", "file_id": <int> }
        """
        u = request.current_user
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        filename       = data.get("filename")
        ciphertext_b64 = data.get("ciphertext")
        nonce_iv_b64   = data.get("nonce_iv")
        auth_tag_b64   = data.get("auth_tag")
        permissions    = data.get("permissions", [])

        if not all([filename, ciphertext_b64, nonce_iv_b64, auth_tag_b64]):
            return jsonify({"error": "filename, ciphertext, nonce_iv, auth_tag required"}), 400

        try:
            ciphertext = b64decode_field(ciphertext_b64, "ciphertext")
            nonce_iv   = b64decode_field(nonce_iv_b64,   "nonce_iv")
            auth_tag   = b64decode_field(auth_tag_b64,   "auth_tag")
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        if len(nonce_iv) != 12:
            return jsonify({"error": "nonce_iv must be exactly 12 bytes for AES-GCM"}), 400

        if len(auth_tag) != 16:
            return jsonify({"error": "auth_tag must be exactly 16 bytes for AES-GCM"}), 400

        if not permissions:
            return jsonify({"error": "permissions list is required"}), 400

        file_obj = File(
            owner_id=u.user_id,
            filename=filename,
            ciphertext=ciphertext,
            nonce_iv=nonce_iv,
            auth_tag=auth_tag,
            fek_version=1,
        )
        db.session.add(file_obj)
        db.session.flush()  # get file_id before committing

        owner_included = False

        for p in permissions:
            target_user_id  = p.get("user_id")
            permission_type = p.get("permission_type")
            wrapped_fek_b64 = p.get("wrapped_fek")
            fek_version     = int(p.get("fek_version", 1))

            if not target_user_id or permission_type not in ("read", "write") or not wrapped_fek_b64:
                db.session.rollback()
                return jsonify({
                    "error": "Each permission entry needs user_id, permission_type (read|write), wrapped_fek"
                }), 400

            if not User.query.get(target_user_id):
                db.session.rollback()
                return jsonify({"error": f"User {target_user_id} not found"}), 404

            try:
                wrapped_fek = b64decode_field(wrapped_fek_b64, "wrapped_fek")
            except ValueError as e:
                db.session.rollback()
                return jsonify({"error": str(e)}), 400

            if target_user_id == u.user_id:
                owner_included = True

            db.session.add(FilePermission(
                file_id=file_obj.file_id,
                user_id=target_user_id,
                permission_type=permission_type,
            ))
            db.session.add(WrappedKey(
                file_id=file_obj.file_id,
                user_id=target_user_id,
                wrapped_fek=wrapped_fek,
                fek_version=fek_version,
            ))

        if not owner_included:
            db.session.rollback()
            return jsonify({"error": "Owner must be included in the permissions list"}), 400

        db.session.commit()
        return jsonify({"message": "File uploaded", "file_id": file_obj.file_id}), 201

    @app.route("/api/files/<int:file_id>", methods=["GET"])
    @require_auth
    def download_file(file_id):
        """
        Download an encrypted file (ciphertext + wrapped FEK for this user).

        ACL enforced: user must have at least read permission.
        Only the requesting user's wrapped FEK is returned — never another user's.

        Response 200:
            {
              "file_id":         <int>,
              "filename":        <str>,
              "ciphertext":      <base64 str>,
              "nonce_iv":        <base64 str>,
              "auth_tag":        <base64 str>,
              "wrapped_fek":     <base64 str>,   # sealed for THIS user
              "fek_version":     <int>,
              "permission_type": "read" | "write"
            }
        """
        u = request.current_user

        file_obj = File.query.get(file_id)
        if not file_obj:
            return jsonify({"error": "File not found"}), 404

        perm = get_permission(file_id, u.user_id)
        if not can_read(perm):
            return jsonify({"error": "Access denied"}), 403

        wrapped_key = WrappedKey.query.filter_by(
            file_id=file_id,
            user_id=u.user_id,
        ).first()
        if not wrapped_key:
            return jsonify({"error": "Wrapped key not found for this user"}), 404

        return jsonify({
            "file_id":         file_obj.file_id,
            "filename":        file_obj.filename,
            "ciphertext":      b64encode_bytes(file_obj.ciphertext),
            "nonce_iv":        b64encode_bytes(file_obj.nonce_iv),
            "auth_tag":        b64encode_bytes(file_obj.auth_tag),
            "wrapped_fek":     b64encode_bytes(wrapped_key.wrapped_fek),
            "fek_version":     wrapped_key.fek_version,
            "permission_type": perm.permission_type,
        }), 200

    @app.route("/api/files/<int:file_id>", methods=["PUT"])
    @require_auth
    def update_file(file_id):
        """
        Overwrite an encrypted file's ciphertext (modify flow).

        The client re-encrypts the plaintext with the SAME FEK but a NEW nonce,
        then sends the new ciphertext here.
        ACL enforced: user must have write permission.

        Request JSON:
            ciphertext  (str) - base64-encoded new ciphertext
            nonce_iv    (str) - base64-encoded new 12-byte nonce
            auth_tag    (str) - base64-encoded new 16-byte GCM auth tag

        Response 200:
            { "message": "File updated" }
        """
        u = request.current_user
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        ciphertext_b64 = data.get("ciphertext")
        nonce_iv_b64   = data.get("nonce_iv")
        auth_tag_b64   = data.get("auth_tag")

        if not all([ciphertext_b64, nonce_iv_b64, auth_tag_b64]):
            return jsonify({"error": "ciphertext, nonce_iv, auth_tag required"}), 400

        file_obj = File.query.get(file_id)
        if not file_obj:
            return jsonify({"error": "File not found"}), 404

        perm = get_permission(file_id, u.user_id)
        if not can_write(perm):
            return jsonify({"error": "Access denied: write permission required"}), 403

        try:
            file_obj.ciphertext = b64decode_field(ciphertext_b64, "ciphertext")
            file_obj.nonce_iv   = b64decode_field(nonce_iv_b64,   "nonce_iv")
            file_obj.auth_tag   = b64decode_field(auth_tag_b64,   "auth_tag")
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        if len(file_obj.nonce_iv) != 12:
            return jsonify({"error": "nonce_iv must be exactly 12 bytes for AES-GCM"}), 400

        if len(file_obj.auth_tag) != 16:
            return jsonify({"error": "auth_tag must be exactly 16 bytes for AES-GCM"}), 400

        db.session.commit()
        return jsonify({"message": "File updated"}), 200

    # ---------- SHARING / ACL ENDPOINTS ----------

    @app.route("/api/files/<int:file_id>/permissions", methods=["GET"])
    @require_auth
    def get_permissions(file_id):
        """
        List all users who have access to a file, and their permission level.
        Only the file owner can call this.

        Response 200:
            [
              {
                "user_id":         <int>,
                "username":        <str>,
                "permission_type": "read" | "write",
                "is_owner":        <bool>
              },
              ...
            ]
        """
        u = request.current_user

        file_obj = File.query.get(file_id)
        if not file_obj:
            return jsonify({"error": "File not found"}), 404

        if file_obj.owner_id != u.user_id:
            return jsonify({"error": "Only the owner can view permissions"}), 403

        perms = FilePermission.query.filter_by(file_id=file_id).all()
        result = []
        for p in perms:
            user = User.query.get(p.user_id)
            result.append({
                "user_id":         p.user_id,
                "username":        user.username if user else None,
                "permission_type": p.permission_type,
                "is_owner":        p.user_id == file_obj.owner_id,
            })

        return jsonify(result), 200

    @app.route("/api/files/<int:file_id>/share", methods=["POST"])
    @require_auth
    def share_file(file_id):
        """
        Grant or update a user's access to a file.
        Only the file owner can call this.

        The owner must wrap the FEK with the recipient's public key client-side
        (sealed box) before calling this endpoint.

        Request JSON:
            target_user_id   (int)  - user to grant access to
            permission_type  (str)  - "read" | "write"
            wrapped_fek      (str)  - base64-encoded FEK wrapped with recipient's public key
            fek_version      (int)  - optional, defaults to current file fek_version

        Response 200:
            { "message": "Access granted", "target_user_id": <int> }
        """
        u = request.current_user
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        file_obj = File.query.get(file_id)
        if not file_obj:
            return jsonify({"error": "File not found"}), 404

        if file_obj.owner_id != u.user_id:
            return jsonify({"error": "Only the owner can share this file"}), 403

        target_user_id  = data.get("target_user_id")
        permission_type = data.get("permission_type")
        wrapped_fek_b64 = data.get("wrapped_fek")
        fek_version     = int(data.get("fek_version", file_obj.fek_version))

        if not target_user_id or permission_type not in ("read", "write") or not wrapped_fek_b64:
            return jsonify({
                "error": "target_user_id, permission_type (read|write), wrapped_fek required"
            }), 400

        if not User.query.get(target_user_id):
            return jsonify({"error": "Target user not found"}), 404

        try:
            wrapped_fek = b64decode_field(wrapped_fek_b64, "wrapped_fek")
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        # Upsert permission
        perm = FilePermission.query.filter_by(file_id=file_id, user_id=target_user_id).first()
        if not perm:
            perm = FilePermission(
                file_id=file_id,
                user_id=target_user_id,
                permission_type=permission_type,
            )
            db.session.add(perm)
        else:
            perm.permission_type = permission_type

        # Upsert wrapped key
        wk = WrappedKey.query.filter_by(file_id=file_id, user_id=target_user_id).first()
        if not wk:
            wk = WrappedKey(
                file_id=file_id,
                user_id=target_user_id,
                wrapped_fek=wrapped_fek,
                fek_version=fek_version,
            )
            db.session.add(wk)
        else:
            wk.wrapped_fek = wrapped_fek
            wk.fek_version = fek_version

        db.session.commit()
        return jsonify({"message": "Access granted", "target_user_id": target_user_id}), 200

    @app.route("/api/files/<int:file_id>/revoke", methods=["POST"])
    @require_auth
    def revoke_user(file_id):
        """
        Revoke a user's access and rekey the file (full rekey policy).

        Because a revoked user previously held the FEK, the file MUST be
        re-encrypted with a brand-new FEK. The owner:
          1. Downloads + decrypts the file client-side.
          2. Generates a new FEK and re-encrypts.
          3. Wraps the new FEK for every remaining authorised user.
          4. Calls this endpoint with the new ciphertext and remaining wrapped keys.

        The owner cannot revoke themselves.

        Request JSON:
            revoked_user_id  (int)   - user to remove
            new_ciphertext   (str)   - base64 re-encrypted ciphertext
            new_nonce_iv     (str)   - base64 new 12-byte nonce
            new_auth_tag     (str)   - base64 new 16-byte GCM auth tag
            fek_version      (int)   - optional, auto-incremented if omitted
            remaining_users  (list)  - [
                {
                  "user_id":    <int>,
                  "wrapped_fek": <base64 str>  # new FEK wrapped for this user
                },
                ...
              ]

        Response 200:
            { "message": "Rekey complete, user revoked" }
        """
        u = request.current_user
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        file_obj = File.query.get(file_id)
        if not file_obj:
            return jsonify({"error": "File not found"}), 404

        if file_obj.owner_id != u.user_id:
            return jsonify({"error": "Only the owner can revoke access"}), 403

        revoked_user_id  = data.get("revoked_user_id")
        new_ciphertext_b64 = data.get("new_ciphertext")
        new_nonce_iv_b64   = data.get("new_nonce_iv")
        new_auth_tag_b64   = data.get("new_auth_tag")
        new_fek_version    = int(data.get("fek_version", file_obj.fek_version + 1))
        remaining_users    = data.get("remaining_users", [])

        if not all([revoked_user_id, new_ciphertext_b64, new_nonce_iv_b64, new_auth_tag_b64]):
            return jsonify({"error": "revoked_user_id, new_ciphertext, new_nonce_iv, new_auth_tag required"}), 400

        # Owner cannot revoke themselves
        if revoked_user_id == u.user_id:
            return jsonify({"error": "Owner cannot revoke their own access"}), 400

        if not FilePermission.query.filter_by(file_id=file_id, user_id=revoked_user_id).first():
            return jsonify({"error": "User does not have access to this file"}), 404

        try:
            file_obj.ciphertext = b64decode_field(new_ciphertext_b64, "new_ciphertext")
            file_obj.nonce_iv   = b64decode_field(new_nonce_iv_b64,   "new_nonce_iv")
            file_obj.auth_tag   = b64decode_field(new_auth_tag_b64,   "new_auth_tag")
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        file_obj.fek_version = new_fek_version

        # Remove revoked user
        FilePermission.query.filter_by(file_id=file_id, user_id=revoked_user_id).delete()
        WrappedKey.query.filter_by(file_id=file_id, user_id=revoked_user_id).delete()

        # Update wrapped keys for remaining users with new FEK
        for entry in remaining_users:
            uid             = entry.get("user_id")
            wrapped_fek_b64 = entry.get("wrapped_fek")

            if not uid or not wrapped_fek_b64:
                db.session.rollback()
                return jsonify({
                    "error": "Each remaining_users entry needs user_id and wrapped_fek"
                }), 400

            try:
                wrapped_fek = b64decode_field(wrapped_fek_b64, "wrapped_fek")
            except ValueError as e:
                db.session.rollback()
                return jsonify({"error": str(e)}), 400

            wk = WrappedKey.query.filter_by(file_id=file_id, user_id=uid).first()
            if not wk:
                db.session.rollback()
                return jsonify({"error": f"No existing wrapped key found for user {uid}"}), 404

            wk.wrapped_fek = wrapped_fek
            wk.fek_version = new_fek_version

        db.session.commit()
        return jsonify({"message": "Rekey complete, user revoked"}), 200

    @app.route("/api/files/<int:file_id>", methods=["DELETE"])
    @require_auth
    def delete_file(file_id):
        """
        Delete a file and all associated permissions / wrapped keys.
        Only the file owner can delete.

        Response 200:
            { "message": "File deleted" }
        """
        u = request.current_user

        file_obj = File.query.get(file_id)
        if not file_obj:
            return jsonify({"error": "File not found"}), 404

        if file_obj.owner_id != u.user_id:
            return jsonify({"error": "Only the owner can delete this file"}), 403

        db.session.delete(file_obj)  # cascades to file_permissions + wrapped_keys
        db.session.commit()
        return jsonify({"message": "File deleted"}), 200

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)