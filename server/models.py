from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), nullable=False)

    owned_files = db.relationship("File", backref="owner", lazy=True, cascade="all, delete")


class File(db.Model):
    __tablename__ = "files"

    file_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)

    ciphertext = db.Column(db.LargeBinary, nullable=False)
    nonce_iv = db.Column(db.LargeBinary, nullable=False)   # store raw bytes
    auth_tag = db.Column(db.LargeBinary, nullable=False)   # store raw bytes

    fek_version = db.Column(db.Integer, nullable=False, default=1)

    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), nullable=False)
    updated_at = db.Column(
        db.TIMESTAMP,
        server_default=db.func.current_timestamp(),
        server_onupdate=db.func.current_timestamp(),
        nullable=False,
    )

    permissions = db.relationship("FilePermission", backref="file", lazy=True, cascade="all, delete-orphan")
    wrapped_keys = db.relationship("WrappedKey", backref="file", lazy=True, cascade="all, delete-orphan")


class FilePermission(db.Model):
    __tablename__ = "file_permissions"

    file_id = db.Column(
        db.Integer,
        db.ForeignKey("files.file_id", ondelete="CASCADE"),
        primary_key=True,
    )
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id", ondelete="CASCADE"),
        primary_key=True,
    )

    permission_type = db.Column(
        db.Enum("read", "write", name="permission_type_enum"),
        nullable=False,
    )

    granted_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), nullable=False)

    user = db.relationship("User", backref=db.backref("file_permissions", lazy=True))


class WrappedKey(db.Model):
    __tablename__ = "wrapped_keys"

    file_id = db.Column(
        db.Integer,
        db.ForeignKey("files.file_id", ondelete="CASCADE"),
        primary_key=True,
    )
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id", ondelete="CASCADE"),
        primary_key=True,
    )

    wrapped_fek = db.Column(db.LargeBinary, nullable=False)
    fek_version = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), nullable=False)

    user = db.relationship("User", backref=db.backref("wrapped_keys", lazy=True))