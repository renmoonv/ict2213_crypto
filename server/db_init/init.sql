-- Use the database created by docker-compose (MYSQL_DATABASE=applied_crypto)
USE applied_crypto;

-- USERS
CREATE TABLE IF NOT EXISTS users (
  user_id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(255) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,      -- Argon2 hash string includes salt/params
  public_key TEXT NOT NULL,         -- PEM/Base64 (or raw base64) public key
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;


-- FILES (ciphertext stored, never plaintext)
CREATE TABLE IF NOT EXISTS files (
  file_id INT AUTO_INCREMENT PRIMARY KEY,
  owner_id INT NOT NULL,
  filename VARCHAR(255) NOT NULL,

  -- AES-256-GCM outputs
  ciphertext LONGBLOB NOT NULL,
  nonce_iv VARBINARY(12) NOT NULL,     -- 12 bytes recommended for GCM
  auth_tag VARBINARY(16) NOT NULL,     -- 16 bytes tag typical for GCM

  fek_version INT NOT NULL DEFAULT 1,  -- increment on rekey (revocation)

  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

  CONSTRAINT fk_files_owner
    FOREIGN KEY (owner_id) REFERENCES users(user_id)
    ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE INDEX idx_files_owner ON files(owner_id);


-- FILE PERMISSIONS (ACL)
-- One row per (file_id, user_id). Permission is read or write.
CREATE TABLE IF NOT EXISTS file_permissions (
  file_id INT NOT NULL,
  user_id INT NOT NULL,
  permission_type ENUM('read','write') NOT NULL,
  granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (file_id, user_id),

  CONSTRAINT fk_perm_file
    FOREIGN KEY (file_id) REFERENCES files(file_id)
    ON DELETE CASCADE,

  CONSTRAINT fk_perm_user
    FOREIGN KEY (user_id) REFERENCES users(user_id)
    ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE INDEX idx_perm_user ON file_permissions(user_id);
CREATE INDEX idx_perm_file ON file_permissions(file_id);


-- WRAPPED KEYS
-- Stores FEK wrapped to each recipient's public key (sealed box / etc)
-- One row per (file_id, user_id). Keep fek_version in sync with files.fek_version.
CREATE TABLE IF NOT EXISTS wrapped_keys (
  file_id INT NOT NULL,
  user_id INT NOT NULL,
  wrapped_fek BLOB NOT NULL,
  fek_version INT NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (file_id, user_id),

  CONSTRAINT fk_wk_file
    FOREIGN KEY (file_id) REFERENCES files(file_id)
    ON DELETE CASCADE,

  CONSTRAINT fk_wk_user
    FOREIGN KEY (user_id) REFERENCES users(user_id)
    ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE INDEX idx_wk_user ON wrapped_keys(user_id);
CREATE INDEX idx_wk_file ON wrapped_keys(file_id);
