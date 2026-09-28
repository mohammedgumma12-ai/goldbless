CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  phone TEXT UNIQUE,
  password_hash TEXT,
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  invite_code TEXT NOT NULL UNIQUE,
  referred_by BIGINT REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS email_otps (
  email TEXT PRIMARY KEY,
  otp_hash TEXT NOT NULL,
  invite_code TEXT,
  phone TEXT,
  password_hash TEXT,
  purpose TEXT NOT NULL DEFAULT 'register' CHECK (purpose IN ('register', 'reset_password', 'withdrawal')),
  expires_at TIMESTAMPTZ NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE email_otps ADD COLUMN IF NOT EXISTS phone TEXT;
ALTER TABLE email_otps ADD COLUMN IF NOT EXISTS password_hash TEXT;
ALTER TABLE email_otps ADD COLUMN IF NOT EXISTS purpose TEXT NOT NULL DEFAULT 'register';
ALTER TABLE email_otps DROP CONSTRAINT IF EXISTS email_otps_purpose_check;
ALTER TABLE email_otps ADD CONSTRAINT email_otps_purpose_check CHECK (purpose IN ('register', 'reset_password', 'withdrawal'));

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS deposits (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  tx_hash TEXT NOT NULL UNIQUE,
  amount NUMERIC(20, 6) NOT NULL CHECK (amount > 0),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed', 'rejected')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS withdrawals (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  wallet_address TEXT NOT NULL,
  amount NUMERIC(20, 6) NOT NULL CHECK (amount >= 20),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'paid', 'rejected')),
  payout_tx_hash TEXT UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS ledger_entries (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  entry_type TEXT NOT NULL CHECK (entry_type IN ('deposit', 'withdrawal')),
  amount NUMERIC(20, 6) NOT NULL CHECK (amount <> 0),
  reference TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS users_phone_unique_idx ON users(phone) WHERE phone IS NOT NULL;
CREATE INDEX IF NOT EXISTS deposits_user_id_idx ON deposits(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS withdrawals_user_id_idx ON withdrawals(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ledger_user_id_idx ON ledger_entries(user_id, created_at DESC);