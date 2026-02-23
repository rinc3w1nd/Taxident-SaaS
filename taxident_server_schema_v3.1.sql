-- ============================================================
-- TAXIDENT — SERVER-SIDE SCHEMA v3.1
-- Zero-Knowledge Encrypted Storage + Anonymous WebAuthn Auth
-- + Advisor Delegation + Per-Record Encryption
-- ============================================================
--
-- DESIGN PRINCIPLES:
--   1. Server never sees plaintext user data
--   2. No email, no username, no PII stored server-side
--   3. Identity = WebAuthn credential public key
--   4. Account recovery via BIP39 mnemonic → deterministic key derivation
--   5. User data stored as per-record encrypted rows (Tuta/Proton model)
--   6. Server retains plaintext structural metadata (dates, types)
--      for filtering, pagination, and grant enforcement
--   7. Rulesets, jurisdictions, treaties are PUBLIC reference data (plaintext)
--
-- KEY DERIVATION MODEL:
--   master_seed (from registration or BIP39 recovery)
--     → HKDF("auth")           → auth_key_seed (WebAuthn binding)
--     → HKDF("scope:<type>")   → scope_master_key (one per vault_type)
--         → HKDF(scope_key, "<period_label>") → period_key
--
--   Each encrypted_record is encrypted with the period_key for its
--   (vault_type, period_label). Non-temporal scopes use the scope_master_key
--   directly (no period derivation).
--
-- ADVISOR DELEGATION:
--   User wraps period_keys with advisor's public key → stored in advisor_grants.
--   Server enforces grant boundaries by filtering on plaintext metadata
--   (vault_type, period_label, record_date >= start_offset) before serving
--   encrypted rows. Advisor decrypts with their private key → unwraps
--   period_key → decrypts individual records.
--
-- ENCRYPTION:
--   AES-256-GCM (WebCrypto-native) default.
--   XChaCha20-Poly1305 optional (requires libsodium).
--   Per-record nonce. Keys never leave client.
--
-- CHANGELOG v3.1:
--   - Added countries lookup table; FK'd from jurisdictions, treaties
--   - Added crypto_algorithms lookup table; FK'd from encrypted_records,
--     advisor_grants, advisor_workspace_messages
--   - Added 'countries' to reference_data_versions CHECK
--
-- ============================================================


-- ============================================================
-- 1. ACCOUNTS & AUTHENTICATION
-- ============================================================

CREATE TABLE accounts (
    id                  TEXT PRIMARY KEY,
    account_fingerprint TEXT NOT NULL UNIQUE,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at        TIMESTAMP
);

CREATE TABLE webauthn_credentials (
    id                  TEXT PRIMARY KEY,
    account_id          TEXT NOT NULL REFERENCES accounts(id),
    credential_id       TEXT NOT NULL UNIQUE,
    public_key          TEXT NOT NULL,
    sign_count          INTEGER NOT NULL DEFAULT 0,
    transports          TEXT,
    device_name         TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at        TIMESTAMP
);

CREATE TABLE recovery_verifiers (
    id                  TEXT PRIMARY KEY,
    account_id          TEXT NOT NULL REFERENCES accounts(id),
    verifier_hash       TEXT NOT NULL,
    algorithm           TEXT NOT NULL DEFAULT 'argon2id',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (account_id)
);

CREATE TABLE auth_challenges (
    id                  TEXT PRIMARY KEY,
    challenge           TEXT NOT NULL UNIQUE,
    challenge_type      TEXT NOT NULL,
    account_id          TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at          TIMESTAMP NOT NULL,

    CHECK (challenge_type IN ('registration', 'authentication', 'recovery'))
);


-- ============================================================
-- 2. LOOKUP TABLES
-- ============================================================

-- 2a. Countries (ISO 3166-1)
-- Canonical country reference. FK'd from jurisdictions, treaties,
-- and used as client-side cache for all country_code fields.

CREATE TABLE countries (
    code            TEXT PRIMARY KEY,            -- ISO 3166-1 alpha-2 (e.g. 'US', 'PT', 'DE')
    name            TEXT NOT NULL,
    alpha3          TEXT NOT NULL UNIQUE,         -- ISO 3166-1 alpha-3 (e.g. 'USA', 'PRT', 'DEU')
    numeric_code    TEXT,                         -- ISO 3166-1 numeric (e.g. '840')
    region          TEXT,                         -- e.g. 'Europe', 'Asia', 'Americas'
    sub_region      TEXT,                         -- e.g. 'Southern Europe', 'Southeast Asia'
    is_eu_member    INTEGER NOT NULL DEFAULT 0,
    is_oecd_member  INTEGER NOT NULL DEFAULT 0,
    has_dn_visa     INTEGER NOT NULL DEFAULT 0,   -- has digital nomad visa programme
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2b. Vault types
-- Canonical list of data scope categories.

CREATE TABLE vault_types (
    id              TEXT PRIMARY KEY,
    display_name    TEXT NOT NULL,
    is_temporal     INTEGER NOT NULL DEFAULT 1,
    description     TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO vault_types (id, display_name, is_temporal, description) VALUES
    ('presence',         'Presence Data',       1, 'Travel intervals and family presence'),
    ('status_modifiers', 'Status Modifiers',    1, 'Visas, tax registrations, domicile, homes, employment'),
    ('assertions',       'Assertions',          1, 'User assertions for subjective rules'),
    ('evaluations',      'Evaluations',         1, 'Residency evaluations and rule results'),
    ('treaty_evals',     'Treaty Evaluations',  1, 'Treaty tiebreaker evaluations'),
    ('day_counts',       'Day Counts',          1, 'Derived day count cache'),
    ('risk_alerts',      'Risk & Projections',  1, 'Risk alerts and simulations'),
    ('audit_log',        'Audit Log',           1, 'Client-side audit trail'),
    ('identity',         'Identity',            0, 'Nationalities and family members'),
    ('settings',         'Settings',            0, 'User preferences and UI state');

-- 2c. Cryptographic algorithms
-- Canonical list of encryption and key-wrapping algorithms.
-- FK'd from encrypted_records, advisor_grants, advisor_workspace_messages.

CREATE TABLE crypto_algorithms (
    id              TEXT PRIMARY KEY,            -- e.g. 'aes-256-gcm'
    algorithm_type  TEXT NOT NULL,               -- 'symmetric', 'asymmetric', 'wrapping', 'kdf'
    display_name    TEXT NOT NULL,
    key_bits        INTEGER,                     -- key length in bits
    nonce_bits      INTEGER,                     -- nonce/IV length in bits
    webcrypto_native INTEGER NOT NULL DEFAULT 0, -- 1 = available via WebCrypto API
    library         TEXT,                        -- required library if not native (e.g. 'libsodium')
    notes           TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (algorithm_type IN ('symmetric', 'asymmetric', 'wrapping', 'kdf'))
);

INSERT INTO crypto_algorithms (id, algorithm_type, display_name, key_bits, nonce_bits, webcrypto_native, library, notes) VALUES
    ('aes-256-gcm',                'symmetric',  'AES-256-GCM',                256, 96,  1, NULL,         'WebCrypto native. Strict nonce non-reuse required.'),
    ('xchacha20-poly1305',         'symmetric',  'XChaCha20-Poly1305',         256, 192, 0, 'libsodium',  'Safe random nonces. Requires libsodium/tweetnacl.'),
    ('x25519-xsalsa20-poly1305',   'wrapping',   'X25519 + XSalsa20-Poly1305', 256, 192, 0, 'libsodium',  'NaCl crypto_box. Requires libsodium.'),
    ('ecdh-p256-aes-256-gcm',      'wrapping',   'ECDH P-256 + AES-256-GCM',   256, 96,  1, NULL,         'WebCrypto native key agreement + encryption.'),
    ('hkdf-sha256',                'kdf',        'HKDF-SHA-256',               256, NULL, 1, NULL,         'Key derivation. WebCrypto native.');


-- ============================================================
-- 3. ENCRYPTED RECORDS
-- ============================================================

CREATE TABLE encrypted_records (
    id                  TEXT PRIMARY KEY,
    account_id          TEXT NOT NULL REFERENCES accounts(id),
    vault_type_id       TEXT NOT NULL REFERENCES vault_types(id),
    period_label        TEXT,
    record_date         TEXT,

    encrypted_payload   TEXT NOT NULL,
    nonce               TEXT NOT NULL,
    encryption_algo_id  TEXT NOT NULL DEFAULT 'aes-256-gcm' REFERENCES crypto_algorithms(id),
    data_version        INTEGER NOT NULL DEFAULT 1,
    size_bytes          INTEGER,

    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE record_history (
    id                  TEXT PRIMARY KEY,
    record_id           TEXT NOT NULL REFERENCES encrypted_records(id),
    data_version        INTEGER NOT NULL,
    encrypted_payload   TEXT NOT NULL,
    nonce               TEXT NOT NULL,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- ============================================================
-- 4. ADVISOR ACCOUNTS & KYC
-- ============================================================

CREATE TABLE advisor_accounts (
    id                      TEXT PRIMARY KEY,
    account_id              TEXT NOT NULL REFERENCES accounts(id),
    delegation_public_key   TEXT NOT NULL,
    kyc_status              TEXT NOT NULL DEFAULT 'pending',
    kyc_verified_at         TIMESTAMP,
    kyc_reference           TEXT,
    display_name_encrypted  TEXT,
    jurisdiction_tags       TEXT,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (kyc_status IN ('pending', 'submitted', 'verified', 'rejected', 'suspended')),
    UNIQUE (account_id)
);


-- ============================================================
-- 5. ADVISOR GRANTS
-- ============================================================

CREATE TABLE advisor_grants (
    id                      TEXT PRIMARY KEY,
    account_id              TEXT NOT NULL REFERENCES accounts(id),
    recipient_type          TEXT NOT NULL,
    advisor_account_id      TEXT REFERENCES advisor_accounts(id),
    opaque_token            TEXT,

    vault_type_id           TEXT NOT NULL REFERENCES vault_types(id),
    period_label            TEXT NOT NULL,

    wrapped_period_key      TEXT NOT NULL,
    wrapping_algo_id        TEXT NOT NULL DEFAULT 'x25519-xsalsa20-poly1305' REFERENCES crypto_algorithms(id),

    start_offset            TEXT,

    granted_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at              TIMESTAMP,
    tombstoned_at           TIMESTAMP,

    CHECK (recipient_type IN ('advisor_id', 'opaque_token')),
    CHECK (
        (recipient_type = 'advisor_id' AND advisor_account_id IS NOT NULL AND opaque_token IS NULL)
        OR
        (recipient_type = 'opaque_token' AND opaque_token IS NOT NULL AND advisor_account_id IS NULL)
    )
);

CREATE UNIQUE INDEX idx_grants_active_advisor
    ON advisor_grants(account_id, advisor_account_id, vault_type_id, period_label)
    WHERE advisor_account_id IS NOT NULL AND tombstoned_at IS NULL;

CREATE UNIQUE INDEX idx_grants_active_token
    ON advisor_grants(account_id, opaque_token, vault_type_id, period_label)
    WHERE opaque_token IS NOT NULL AND tombstoned_at IS NULL;


-- ============================================================
-- 6. ADVISOR COMMUNICATION WORKSPACE (STUB)
-- ============================================================

CREATE TABLE advisor_workspace_messages (
    id                      TEXT PRIMARY KEY,
    grant_id                TEXT NOT NULL REFERENCES advisor_grants(id),
    sender_type             TEXT NOT NULL,
    encrypted_payload       TEXT NOT NULL,
    nonce                   TEXT NOT NULL,
    encryption_algo_id      TEXT NOT NULL DEFAULT 'aes-256-gcm' REFERENCES crypto_algorithms(id),
    payload_type            TEXT NOT NULL DEFAULT 'message',
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (sender_type IN ('user', 'advisor')),
    CHECK (payload_type IN ('message', 'document', 'annotation'))
);


-- ============================================================
-- 7. PUBLIC REFERENCE DATA — PLAINTEXT
-- ============================================================

CREATE TABLE jurisdictions (
    id              TEXT PRIMARY KEY,
    country_code    TEXT NOT NULL REFERENCES countries(code),
    country_name    TEXT NOT NULL,
    sub_region      TEXT,
    tax_year_type   TEXT NOT NULL DEFAULT 'calendar',
    tax_year_start  TEXT,
    notes           TEXT,

    CHECK (tax_year_type IN ('calendar', 'fiscal', 'custom'))
);

CREATE TABLE rulesets (
    id              TEXT PRIMARY KEY,
    jurisdiction_id TEXT NOT NULL REFERENCES jurisdictions(id),
    version         INTEGER NOT NULL,
    effective_from  DATE NOT NULL,
    effective_to    DATE,
    status          TEXT NOT NULL DEFAULT 'draft',
    author          TEXT,
    change_notes    TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (status IN ('draft', 'active', 'superseded')),
    UNIQUE (jurisdiction_id, version)
);

CREATE TABLE rules (
    id                  TEXT PRIMARY KEY,
    ruleset_id          TEXT NOT NULL REFERENCES rulesets(id),
    rule_code           TEXT NOT NULL,
    rule_name           TEXT NOT NULL,
    description         TEXT,
    determination_type  TEXT NOT NULL,
    authority_type      TEXT NOT NULL,
    authority_reference TEXT,
    evaluation_order    INTEGER NOT NULL,
    rule_logic_ref      TEXT NOT NULL,
    output_template     TEXT,
    notes               TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (determination_type IN ('mechanical', 'structured_subjective', 'irreducibly_subjective')),
    CHECK (authority_type IN ('statute', 'regulation', 'admin_guidance', 'case_law')),
    UNIQUE (ruleset_id, rule_code)
);

CREATE TABLE rule_parameters (
    id              TEXT PRIMARY KEY,
    rule_id         TEXT NOT NULL REFERENCES rules(id),
    param_key       TEXT NOT NULL,
    param_value     TEXT NOT NULL,
    param_type      TEXT NOT NULL,
    description     TEXT,

    CHECK (param_type IN ('integer', 'boolean', 'text', 'date', 'decimal')),
    UNIQUE (rule_id, param_key)
);

CREATE TABLE treaties (
    id                      TEXT PRIMARY KEY,
    country_a_code          TEXT NOT NULL REFERENCES countries(code),
    country_b_code          TEXT NOT NULL REFERENCES countries(code),
    treaty_name             TEXT NOT NULL,
    effective_from          DATE NOT NULL,
    effective_to            DATE,
    country_a_saving_clause INTEGER NOT NULL DEFAULT 0,
    country_b_saving_clause INTEGER NOT NULL DEFAULT 0,
    treaty_reference        TEXT,
    notes                   TEXT,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (country_a_code, country_b_code, effective_from)
);

CREATE TABLE treaty_tiebreaker_steps (
    id                  TEXT PRIMARY KEY,
    treaty_id           TEXT NOT NULL REFERENCES treaties(id),
    step_order          INTEGER NOT NULL,
    test_name           TEXT NOT NULL,
    determination_type  TEXT NOT NULL,
    rule_logic_ref      TEXT,
    description         TEXT,

    CHECK (test_name IN (
        'permanent_home', 'vital_interests', 'habitual_abode',
        'nationality', 'mutual_agreement'
    )),
    CHECK (determination_type IN ('mechanical', 'structured_subjective', 'irreducibly_subjective')),
    UNIQUE (treaty_id, step_order)
);


-- ============================================================
-- 8. REFERENCE DATA VERSIONING
-- ============================================================

CREATE TABLE reference_data_versions (
    id              TEXT PRIMARY KEY,
    data_type       TEXT NOT NULL UNIQUE,
    current_version INTEGER NOT NULL DEFAULT 1,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (data_type IN ('countries', 'jurisdictions', 'rulesets', 'rules', 'treaties'))
);


-- ============================================================
-- 9. SYNC METADATA
-- ============================================================

CREATE TABLE sync_cursors (
    id              TEXT PRIMARY KEY,
    account_id      TEXT NOT NULL REFERENCES accounts(id),
    device_id       TEXT NOT NULL,
    vault_type_id   TEXT NOT NULL REFERENCES vault_types(id),
    period_label    TEXT,
    last_synced_at  TIMESTAMP NOT NULL,
    last_version    INTEGER NOT NULL DEFAULT 0,

    UNIQUE (account_id, device_id, vault_type_id, period_label)
);


-- ============================================================
-- 10. RATE LIMITING & ABUSE PREVENTION
-- ============================================================

CREATE TABLE rate_limit_events (
    id              TEXT PRIMARY KEY,
    account_id      TEXT,
    ip_hash         TEXT,
    event_type      TEXT NOT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (event_type IN ('auth_attempt', 'vault_write', 'recovery_attempt', 'api_call'))
);


-- ============================================================
-- INDEXES
-- ============================================================

-- Auth
CREATE INDEX idx_webauthn_account ON webauthn_credentials(account_id);
CREATE INDEX idx_webauthn_credential_id ON webauthn_credentials(credential_id);
CREATE INDEX idx_challenges_expires ON auth_challenges(expires_at);

-- Countries
CREATE INDEX idx_countries_region ON countries(region);
CREATE INDEX idx_countries_alpha3 ON countries(alpha3);

-- Vault types
CREATE INDEX idx_vault_types_temporal ON vault_types(is_temporal);

-- Crypto algorithms
CREATE INDEX idx_crypto_algo_type ON crypto_algorithms(algorithm_type);

-- Encrypted records
CREATE INDEX idx_records_account ON encrypted_records(account_id);
CREATE INDEX idx_records_account_type ON encrypted_records(account_id, vault_type_id);
CREATE INDEX idx_records_account_type_period ON encrypted_records(account_id, vault_type_id, period_label);
CREATE INDEX idx_records_account_type_date ON encrypted_records(account_id, vault_type_id, record_date);
CREATE INDEX idx_records_updated ON encrypted_records(account_id, updated_at);
CREATE INDEX idx_records_algo ON encrypted_records(encryption_algo_id);

-- Record history
CREATE INDEX idx_record_history_record ON record_history(record_id, data_version);

-- Advisor
CREATE INDEX idx_advisor_account ON advisor_accounts(account_id);
CREATE INDEX idx_advisor_kyc_status ON advisor_accounts(kyc_status);
CREATE INDEX idx_grants_account ON advisor_grants(account_id);
CREATE INDEX idx_grants_advisor ON advisor_grants(advisor_account_id) WHERE advisor_account_id IS NOT NULL;
CREATE INDEX idx_grants_token ON advisor_grants(opaque_token) WHERE opaque_token IS NOT NULL;
CREATE INDEX idx_grants_period ON advisor_grants(account_id, vault_type_id, period_label);
CREATE INDEX idx_grants_wrapping_algo ON advisor_grants(wrapping_algo_id);
CREATE INDEX idx_workspace_grant ON advisor_workspace_messages(grant_id, created_at);
CREATE INDEX idx_workspace_algo ON advisor_workspace_messages(encryption_algo_id);

-- Sync
CREATE INDEX idx_sync_cursors_account ON sync_cursors(account_id, device_id);

-- Reference data
CREATE INDEX idx_jurisdictions_country ON jurisdictions(country_code);
CREATE INDEX idx_rulesets_jurisdiction ON rulesets(jurisdiction_id);
CREATE INDEX idx_rules_ruleset ON rules(ruleset_id, evaluation_order);
CREATE INDEX idx_treaties_country_a ON treaties(country_a_code);
CREATE INDEX idx_treaties_country_b ON treaties(country_b_code);
CREATE INDEX idx_treaty_steps ON treaty_tiebreaker_steps(treaty_id, step_order);

-- Rate limiting
CREATE INDEX idx_rate_limit_account ON rate_limit_events(account_id, event_type, created_at);
CREATE INDEX idx_rate_limit_ip ON rate_limit_events(ip_hash, event_type, created_at);
