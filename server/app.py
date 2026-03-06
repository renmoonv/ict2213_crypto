from flask import Flask, request, jsonify
from config import Config
from models import db, User, File, FilePermission, WrappedKey
from functools import wraps
import base64


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)

    # ---------- AUTH HELPER ----------

    def require_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            username = request.headers.get("X-Username")
            password_hash = request.headers.get("X-Password-Hash")

            if not username or not password_hash:
                data = request.get_json(silent=True) or {}
                username = username or data.get("username")
                password_hash = password_hash or data.get("password_hash")

            if not username or not password_hash:
                return jsonify({"error": "Missing credentials"}), 401

            user = User.query.filter_by(username=username).first()
            if not user or user.password_hash != password_hash:
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

    # ---------- ENDPOINTS ----------

    @app.route("/api/register", methods=["POST"])
    def register():
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        username = data.get("username")
        password_hash = data.get("password_hash")
        public_key = data.get("public_key")

        if not username or not password_hash or not public_key:
            return jsonify({"error": "username, password_hash, public_key required"}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({"error": "Username already taken"}), 409

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
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        username = data.get("username")
        password_hash = data.get("password_hash")

        if not username or not password_hash:
            return jsonify({"error": "username and password_hash required"}), 400

        user = User.query.filter_by(username=username).first()
        if not user or user.password_hash != password_hash:
            return jsonify({"error": "Invalid username or password"}), 401

        return jsonify({"message": "Login OK", "user_id": user.user_id}), 200

    @app.route("/api/users/<int:user_id>/public-key", methods=["GET"])
    @require_auth
    def get_public_key(user_id):
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404

        return jsonify({
            "user_id": user.user_id,
            "username": user.username,
            "public_key": user.public_key
        }), 200

    @app.route("/api/files", methods=["GET"])
    @require_auth
    def list_files():
        u = request.current_user

        perms = (
            FilePermission.query
            .filter_by(user_id=u.user_id)
            .join(File, File.file_id == FilePermission.file_id)
            .add_entity(File)
            .all()
        )

        result = []
        for perm, file_obj in perms:
            wrapped_key = WrappedKey.query.filter_by(
                file_id=file_obj.file_id,
                user_id=u.user_id
            ).first()

            result.append({
                "file_id": file_obj.file_id,
                "filename": file_obj.filename,
                "owner_id": file_obj.owner_id,
                "permission_type": perm.permission_type,
                "fek_version": wrapped_key.fek_version if wrapped_key else None,
            })

        return jsonify(result), 200

    @app.route("/api/files", methods=["POST"])
    @require_auth
    def upload_file():
        u = request.current_user
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        filename = data.get("filename")
        ciphertext_b64 = data.get("ciphertext")
        nonce_iv_b64 = data.get("nonce_iv")
        auth_tag_b64 = data.get("auth_tag")
        permissions = data.get("permissions", [])

        if not all([filename, ciphertext_b64, nonce_iv_b64, auth_tag_b64]):
            return jsonify({"error": "Missing file fields"}), 400

        try:
            ciphertext = b64decode_field(ciphertext_b64, "ciphertext")
            nonce_iv = b64decode_field(nonce_iv_b64, "nonce_iv")
            auth_tag = b64decode_field(auth_tag_b64, "auth_tag")
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        file_obj = File(
            owner_id=u.user_id,
            filename=filename,
            ciphertext=ciphertext,
            nonce_iv=nonce_iv,
            auth_tag=auth_tag,
            fek_version=1,
        )
        db.session.add(file_obj)
        db.session.flush()

        if not permissions:
            db.session.rollback()
            return jsonify({"error": "permissions list is required"}), 400

        owner_included = False

        for p in permissions:
            target_user_id = p.get("user_id")
            permission_type = p.get("permission_type")
            wrapped_fek_b64 = p.get("wrapped_fek")
            fek_version = int(p.get("fek_version", 1))

            if not target_user_id or permission_type not in ("read", "write") or not wrapped_fek_b64:
                db.session.rollback()
                return jsonify({
                    "error": "Each permission needs user_id, permission_type, wrapped_fek"
                }), 400

            target_user = User.query.get(target_user_id)
            if not target_user:
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
            return jsonify({"error": "Owner must be included in permissions"}), 400

        db.session.commit()
        return jsonify({"message": "File uploaded", "file_id": file_obj.file_id}), 201

    @app.route("/api/files/<int:file_id>", methods=["GET"])
    @require_auth
    def download_file(file_id):
        u = request.current_user

        perm = get_permission(file_id, u.user_id)
        if not can_read(perm):
            return jsonify({"error": "No read permission"}), 403

        file_obj = File.query.get(file_id)
        if not file_obj:
            return jsonify({"error": "File not found"}), 404

        wrapped_key = WrappedKey.query.filter_by(
            file_id=file_id,
            user_id=u.user_id
        ).first()
        if not wrapped_key:
            return jsonify({"error": "Wrapped key not found"}), 404

        return jsonify({
            "file_id": file_obj.file_id,
            "filename": file_obj.filename,
            "ciphertext": b64encode_bytes(file_obj.ciphertext),
            "nonce_iv": b64encode_bytes(file_obj.nonce_iv),
            "auth_tag": b64encode_bytes(file_obj.auth_tag),
            "wrapped_fek": b64encode_bytes(wrapped_key.wrapped_fek),
            "fek_version": wrapped_key.fek_version,
            "permission_type": perm.permission_type,
        }), 200

    @app.route("/api/files/<int:file_id>", methods=["PUT"])
    @require_auth
    def update_file(file_id):
        u = request.current_user
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        ciphertext_b64 = data.get("ciphertext")
        nonce_iv_b64 = data.get("nonce_iv")
        auth_tag_b64 = data.get("auth_tag")

        if not all([ciphertext_b64, nonce_iv_b64, auth_tag_b64]):
            return jsonify({"error": "Missing fields"}), 400

        perm = get_permission(file_id, u.user_id)
        if not can_write(perm):
            return jsonify({"error": "No write permission"}), 403

        file_obj = File.query.get(file_id)
        if not file_obj:
            return jsonify({"error": "File not found"}), 404

        try:
            file_obj.ciphertext = b64decode_field(ciphertext_b64, "ciphertext")
            file_obj.nonce_iv = b64decode_field(nonce_iv_b64, "nonce_iv")
            file_obj.auth_tag = b64decode_field(auth_tag_b64, "auth_tag")
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        db.session.commit()
        return jsonify({"message": "File updated"}), 200

    @app.route("/api/files/<int:file_id>/share", methods=["POST"])
    @require_auth
    def share_file(file_id):
        u = request.current_user
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        file_obj = File.query.get(file_id)
        if not file_obj:
            return jsonify({"error": "File not found"}), 404

        if file_obj.owner_id != u.user_id:
            return jsonify({"error": "Only owner can share file"}), 403

        target_user_id = data.get("target_user_id")
        permission_type = data.get("permission_type")
        wrapped_fek_b64 = data.get("wrapped_fek")
        fek_version = int(data.get("fek_version", file_obj.fek_version))

        if not target_user_id or permission_type not in ("read", "write") or not wrapped_fek_b64:
            return jsonify({
                "error": "target_user_id, permission_type, wrapped_fek required"
            }), 400

        target_user = User.query.get(target_user_id)
        if not target_user:
            return jsonify({"error": "Target user not found"}), 404

        try:
            wrapped_fek = b64decode_field(wrapped_fek_b64, "wrapped_fek")
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        perm = FilePermission.query.filter_by(
            file_id=file_id,
            user_id=target_user_id
        ).first()
        if not perm:
            perm = FilePermission(
                file_id=file_id,
                user_id=target_user_id,
                permission_type=permission_type,
            )
            db.session.add(perm)
        else:
            perm.permission_type = permission_type

        wk = WrappedKey.query.filter_by(
            file_id=file_id,
            user_id=target_user_id
        ).first()
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
        return jsonify({"message": "Share updated"}), 200

    @app.route("/api/files/<int:file_id>/revoke", methods=["POST"])
    @require_auth
    def revoke_user(file_id):
        u = request.current_user
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        file_obj = File.query.get(file_id)
        if not file_obj:
            return jsonify({"error": "File not found"}), 404

        if file_obj.owner_id != u.user_id:
            return jsonify({"error": "Only owner can revoke file access"}), 403

        revoked_user_id = data.get("revoked_user_id")
        new_ciphertext_b64 = data.get("new_ciphertext")
        new_nonce_iv_b64 = data.get("new_nonce_iv")
        new_auth_tag_b64 = data.get("new_auth_tag")
        new_fek_version = int(data.get("fek_version", file_obj.fek_version + 1))
        remaining_users = data.get("remaining_users", [])

        if not all([revoked_user_id, new_ciphertext_b64, new_nonce_iv_b64, new_auth_tag_b64]):
            return jsonify({"error": "Missing fields"}), 400

        try:
            file_obj.ciphertext = b64decode_field(new_ciphertext_b64, "new_ciphertext")
            file_obj.nonce_iv = b64decode_field(new_nonce_iv_b64, "new_nonce_iv")
            file_obj.auth_tag = b64decode_field(new_auth_tag_b64, "new_auth_tag")
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        file_obj.fek_version = new_fek_version

        FilePermission.query.filter_by(file_id=file_id, user_id=revoked_user_id).delete()
        WrappedKey.query.filter_by(file_id=file_id, user_id=revoked_user_id).delete()

        for entry in remaining_users:
            uid = entry.get("user_id")
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
                return jsonify({"error": f"WrappedKey missing for user {uid}"}), 404

            wk.wrapped_fek = wrapped_fek
            wk.fek_version = new_fek_version

        db.session.commit()
        return jsonify({"message": "Rekey + revoke applied"}), 200

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)