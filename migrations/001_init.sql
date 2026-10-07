-- Amanah Auth - PostgreSQL schema (v1)
-- Semua waktu disimpan sebagai TIMESTAMPTZ (UTC).

BEGIN;

CREATE TABLE users (
    id                  UUID         PRIMARY KEY,
    full_name           VARCHAR(100) NOT NULL,
    email               VARCHAR(254) NOT NULL,
    phone               VARCHAR(16)  NOT NULL,                -- format E.164, mis. +6281234567890
    password_hash       VARCHAR(100) NOT NULL,                -- bcrypt
    failed_login_count  SMALLINT     NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    last_login_at       TIMESTAMPTZ,
    terms_accepted_at   TIMESTAMPTZ  NOT NULL,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_users_email        UNIQUE (email),
    CONSTRAINT uq_users_phone        UNIQUE (phone),
    CONSTRAINT ck_users_email_lower  CHECK (email = lower(email)),
    CONSTRAINT ck_users_phone_e164   CHECK (phone ~ '^\+[1-9][0-9]{7,14}$'),
    CONSTRAINT ck_users_failed_count CHECK (failed_login_count >= 0)
);

CREATE TABLE otp_codes (
    id           UUID         PRIMARY KEY,
    user_id      UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose      VARCHAR(30)  NOT NULL,
    channel      VARCHAR(10)  NOT NULL,
    target       VARCHAR(254) NOT NULL,                       -- email / nomor WA tujuan
    code_hash    CHAR(64)     NOT NULL,                       -- HMAC-SHA256(code), kode asli tidak disimpan
    attempts     SMALLINT     NOT NULL DEFAULT 0,
    expires_at   TIMESTAMPTZ  NOT NULL,
    consumed_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT ck_otp_purpose  CHECK (purpose IN ('login_whatsapp', 'reset_password')),
    CONSTRAINT ck_otp_channel  CHECK (channel IN ('whatsapp', 'email')),
    CONSTRAINT ck_otp_attempts CHECK (attempts >= 0),
    CONSTRAINT ck_otp_expiry   CHECK (expires_at > created_at)
);
-- Hanya boleh ada 1 OTP aktif per (target, purpose)
CREATE UNIQUE INDEX uq_otp_active   ON otp_codes (target, purpose) WHERE consumed_at IS NULL;
CREATE INDEX idx_otp_latest         ON otp_codes (target, purpose, created_at DESC);
CREATE INDEX idx_otp_user_id        ON otp_codes (user_id);
CREATE INDEX idx_otp_expires_at     ON otp_codes (expires_at);

CREATE TABLE refresh_tokens (
    id          UUID         PRIMARY KEY,
    user_id     UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  CHAR(64)     NOT NULL,                        -- SHA-256 dari token
    expires_at  TIMESTAMPTZ  NOT NULL,
    revoked_at  TIMESTAMPTZ,
    ip_address  VARCHAR(45),
    user_agent  VARCHAR(255),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_refresh_token_hash UNIQUE (token_hash)
);
CREATE INDEX idx_refresh_user_active ON refresh_tokens (user_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_refresh_expires_at  ON refresh_tokens (expires_at);

CREATE TABLE password_reset_tokens (
    id          UUID         PRIMARY KEY,
    user_id     UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  CHAR(64)     NOT NULL,
    expires_at  TIMESTAMPTZ  NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_reset_token_hash UNIQUE (token_hash)
);
CREATE INDEX idx_reset_user_id    ON password_reset_tokens (user_id);
CREATE INDEX idx_reset_expires_at ON password_reset_tokens (expires_at);

CREATE TABLE password_histories (
    id             BIGSERIAL    PRIMARY KEY,
    user_id        UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash  VARCHAR(100) NOT NULL,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX idx_pwhist_user_created ON password_histories (user_id, created_at DESC);

COMMIT;
