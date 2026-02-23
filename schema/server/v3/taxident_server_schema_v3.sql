-- ============================================================
-- TAXIDENT — SERVER-SIDE SCHEMA v3
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
-- 2. VAULT TYPE REGISTRY
-- ============================================================
--
-- Canonical list of vault types. All references to vault_type
-- in other tables are FK'd here. Server can validate types
-- without relying on CHECK constraints or free-text conventions.

CREATE TABLE vault_types (
    id              TEXT PRIMARY KEY,         -- e.g. 'presence', 'assertions'
    display_name    TEXT NOT NULL,            -- human-readable label
    is_temporal     INTEGER NOT NULL DEFAULT 1,  -- 1 = period-scoped, 0 = not
    description     TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Seed data
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


-- ============================================================
-- 3. ENCRYPTED RECORDS (replaces encrypted_vaults)
-- ============================================================
--
-- Per-record encryption following the Tuta/Proton model.
-- Each logical record is one row. Plaintext metadata enables
-- server-side filtering, pagination, and grant enforcement.
-- Encrypted payload is opaque to the server.
--
-- record_date is a coarse plaintext date for server-side
-- filtering (e.g. advisor start_offset enforcement).
-- Granularity: date for presence, month for evaluations.
-- Does not leak record content — only temporal position.

CREATE TABLE encrypted_records (
    id                  TEXT PRIMARY KEY,
    account_id          TEXT NOT NULL REFERENCES accounts(id),
    vault_type_id       TEXT NOT NULL REFERENCES vault_types(id),
    period_label        TEXT,                    -- e.g. '2025-Q1'; NULL for non-temporal
    record_date         TEXT,                    -- plaintext ISO 8601 date for filtering
                                                 -- NULL for non-temporal records

    encrypted_payload   TEXT NOT NULL,           -- base64-encoded per-record ciphertext
    nonce               TEXT NOT NULL,           -- base64-encoded, unique per record
    encryption_algo     TEXT NOT NULL DEFAULT 'aes-256-gcm',
    data_version        INTEGER NOT NULL DEFAULT 1,  -- schema version of plaintext record
    size_bytes          INTEGER,

    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Record history for conflict resolution / rollback
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
--
-- Server enforces grants by filtering encrypted_records:
--   WHERE vault_type_id = grant.vault_type_id
--     AND period_label = grant.period_label
--     AND (grant.start_offset IS NULL OR record_date >= grant.start_offset)
--     AND grant.tombstoned_at IS NULL
--     AND (grant.expires_at IS NULL OR grant.expires_at > NOW())
--
-- start_offset is now cryptographically meaningful: the server
-- withholds records before the offset. The advisor never receives
-- the ciphertext, so cannot decrypt what was never transmitted.

CREATE TABLE advisor_grants (
    id                      TEXT PRIMARY KEY,
    account_id              TEXT NOT NULL REFERENCES accounts(id),
    recipient_type          TEXT NOT NULL,
    advisor_account_id      TEXT REFERENCES advisor_accounts(id),
    opaque_token            TEXT,

    vault_type_id           TEXT NOT NULL REFERENCES vault_types(id),
    period_label            TEXT NOT NULL,

    wrapped_period_key      TEXT NOT NULL,
    wrapping_algo           TEXT NOT NULL DEFAULT 'x25519-xsalsa20-poly1305',

    start_offset            TEXT,                -- ISO 8601 date; server-enforced filter

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
    country_code    TEXT NOT NULL,
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
    country_a_code          TEXT NOT NULL,
    country_b_code          TEXT NOT NULL,
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

    CHECK (data_type IN ('jurisdictions', 'rulesets', 'rules', 'treaties'))
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

-- Vault types
CREATE INDEX idx_vault_types_temporal ON vault_types(is_temporal);

-- Encrypted records (core query paths)
CREATE INDEX idx_records_account ON encrypted_records(account_id);
CREATE INDEX idx_records_account_type ON encrypted_records(account_id, vault_type_id);
CREATE INDEX idx_records_account_type_period ON encrypted_records(account_id, vault_type_id, period_label);
CREATE INDEX idx_records_account_type_date ON encrypted_records(account_id, vault_type_id, record_date);
CREATE INDEX idx_records_updated ON encrypted_records(account_id, updated_at);

-- Record history
CREATE INDEX idx_record_history_record ON record_history(record_id, data_version);

-- Advisor
CREATE INDEX idx_advisor_account ON advisor_accounts(account_id);
CREATE INDEX idx_advisor_kyc_status ON advisor_accounts(kyc_status);
CREATE INDEX idx_grants_account ON advisor_grants(account_id);
CREATE INDEX idx_grants_advisor ON advisor_grants(advisor_account_id) WHERE advisor_account_id IS NOT NULL;
CREATE INDEX idx_grants_token ON advisor_grants(opaque_token) WHERE opaque_token IS NOT NULL;
CREATE INDEX idx_grants_period ON advisor_grants(account_id, vault_type_id, period_label);
CREATE INDEX idx_workspace_grant ON advisor_workspace_messages(grant_id, created_at);

-- Sync
CREATE INDEX idx_sync_cursors_account ON sync_cursors(account_id, device_id);

-- Reference data
CREATE INDEX idx_rulesets_jurisdiction ON rulesets(jurisdiction_id);
CREATE INDEX idx_rules_ruleset ON rules(ruleset_id, evaluation_order);
CREATE INDEX idx_treaty_steps ON treaty_tiebreaker_steps(treaty_id, step_order);

-- Rate limiting
CREATE INDEX idx_rate_limit_account ON rate_limit_events(account_id, event_type, created_at);
CREATE INDEX idx_rate_limit_ip ON rate_limit_events(ip_hash, event_type, created_at);
