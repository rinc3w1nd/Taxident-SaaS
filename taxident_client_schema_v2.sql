-- ============================================================
-- TAXIDENT — CLIENT-SIDE SCHEMA v2 (SQLite)
-- Runs in browser (sql.js / wa-sqlite + OPFS) or native wrapper
-- ============================================================
--
-- CHANGES FROM v1:
--   - Added period_label to all period-scoped tables
--   - Added _scope_keys table for local scope key management
--   - Added _advisor_grants_local for tracking outbound grants
--   - Updated _sync_state to include period_label
--   - All other tables unchanged
--
-- PERIOD LABELLING:
--   Records are tagged with a period_label at write time.
--   The label determines which derived key encrypts the record
--   when syncing to the server vault.
--
--   Format: 'YYYY-QN' (e.g. '2025-Q1')
--   Client derives: HKDF(scope_master_key, period_label) → period_key
--   Non-temporal data (identity, settings) has NULL period_label.
--
-- ============================================================


-- ============================================================
-- 0. LOCAL METADATA (UPDATED)
-- ============================================================

-- Tracks which server vaults have been synced and their versions
-- UPDATED: added period_label to track per-period sync state
CREATE TABLE _sync_state (
    vault_type      TEXT NOT NULL,
    period_label    TEXT,                     -- NULL for non-temporal vaults
    local_version   INTEGER NOT NULL DEFAULT 0,
    server_version  INTEGER NOT NULL DEFAULT 0,
    last_synced_at  TEXT,
    dirty           INTEGER NOT NULL DEFAULT 0,

    PRIMARY KEY (vault_type, period_label)
);

CREATE TABLE _reference_cache (
    data_type       TEXT PRIMARY KEY,
    cached_version  INTEGER NOT NULL DEFAULT 0,
    last_fetched_at TEXT
);

CREATE TABLE _device (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL
);
-- Expected rows:
--   device_id       → UUID generated on first run
--   account_id      → from server registration
--   encryption_algo → 'xchacha20-poly1305' or 'aes-256-gcm'


-- ============================================================
-- 0a. SCOPE KEY MANAGEMENT (NEW)
-- ============================================================
--
-- Tracks the scope master keys derived from the master seed.
-- The actual key material is held in memory only (derived on
-- unlock from master seed). This table stores metadata about
-- which scopes exist and their derivation paths.
--
-- This table is NOT synced to the server. It is local-only
-- and reconstructable from the master seed at any time.

CREATE TABLE _scope_keys (
    scope_name          TEXT PRIMARY KEY,         -- e.g. 'presence', 'status_modifiers', 'settings'
    derivation_path     TEXT NOT NULL,            -- e.g. 'scope:presence'
    is_temporal         INTEGER NOT NULL DEFAULT 1,  -- 1 = period-scoped, 0 = no period derivation
    period_granularity  TEXT NOT NULL DEFAULT 'quarterly',
                                                  -- 'quarterly', 'monthly', 'annual'
                                                  -- client convention; can change per scope if needed
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Seed rows (inserted on first run / account creation):
-- INSERT INTO _scope_keys VALUES ('presence',         'scope:presence',         1, 'quarterly', ...);
-- INSERT INTO _scope_keys VALUES ('status_modifiers', 'scope:status_modifiers', 1, 'quarterly', ...);
-- INSERT INTO _scope_keys VALUES ('assertions',       'scope:assertions',       1, 'quarterly', ...);
-- INSERT INTO _scope_keys VALUES ('evaluations',      'scope:evaluations',      1, 'quarterly', ...);
-- INSERT INTO _scope_keys VALUES ('treaty_evals',     'scope:treaty_evals',     1, 'quarterly', ...);
-- INSERT INTO _scope_keys VALUES ('day_counts',       'scope:day_counts',       1, 'quarterly', ...);
-- INSERT INTO _scope_keys VALUES ('risk_alerts',      'scope:risk_alerts',      1, 'quarterly', ...);
-- INSERT INTO _scope_keys VALUES ('audit_log',        'scope:audit_log',        1, 'quarterly', ...);
-- INSERT INTO _scope_keys VALUES ('identity',         'scope:identity',         0, 'quarterly', ...);
-- INSERT INTO _scope_keys VALUES ('settings',         'scope:settings',         0, 'quarterly', ...);


-- ============================================================
-- 0b. OUTBOUND GRANT TRACKING (NEW)
-- ============================================================
--
-- Local record of grants the user has issued to advisors.
-- Mirrors server-side advisor_grants but from the user's
-- perspective. Used to:
--   - Show the user who has access to what
--   - Drive auto-renewal of rolling window grants
--   - Track tombstoned grants locally
--
-- This table is NOT synced as a vault. Grant operations are
-- direct API calls to the server.

CREATE TABLE _advisor_grants_local (
    server_grant_id     TEXT PRIMARY KEY,         -- matches advisor_grants.id on server
    recipient_type      TEXT NOT NULL,            -- 'advisor_id' | 'opaque_token'
    recipient_label     TEXT,                    -- local display label (e.g. "Maria - PT tax")
                                                 -- stored locally, never sent to server
    advisor_account_id  TEXT,                    -- for 'advisor_id' type
    opaque_token_hash   TEXT,                    -- for 'opaque_token' type

    vault_type          TEXT NOT NULL,
    period_label        TEXT NOT NULL,
    start_offset        TEXT,                    -- ISO 8601 date

    granted_at          TEXT NOT NULL,
    expires_at          TEXT,
    tombstoned_at       TEXT,

    -- Rolling window management
    rolling_window      INTEGER NOT NULL DEFAULT 0,  -- 1 = auto-renew next period
    window_periods      INTEGER,                     -- number of periods in rolling window
                                                     -- e.g. 4 = rolling 4 quarters = ~1 year

    CHECK (recipient_type IN ('advisor_id', 'opaque_token'))
);


-- ============================================================
-- 1. IDENTITY
-- ============================================================
-- UNCHANGED — non-temporal scope (period_label NULL on sync)

CREATE TABLE nationalities (
    id                          TEXT PRIMARY KEY,
    country_code                TEXT NOT NULL,
    nationality_type            TEXT NOT NULL CHECK (nationality_type IN ('citizen', 'permanent_resident', 'national')),
    effective_from              TEXT NOT NULL,
    effective_to                TEXT,
    citizenship_based_taxation  INTEGER NOT NULL DEFAULT 0,
    created_at                  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE family_members (
    id              TEXT PRIMARY KEY,
    relationship    TEXT NOT NULL CHECK (relationship IN ('spouse', 'dependent', 'partner')),
    display_name    TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);


-- ============================================================
-- 2. PRESENCE DATA (UPDATED — period_label added)
-- ============================================================

CREATE TABLE presence_intervals (
    id              TEXT PRIMARY KEY,
    country_code    TEXT NOT NULL,
    sub_region      TEXT,
    arrival_date    TEXT NOT NULL,
    departure_date  TEXT,
    source_type     TEXT NOT NULL DEFAULT 'manual' CHECK (source_type IN ('manual', 'csv', 'api', 'derived')),
    confidence      TEXT NOT NULL DEFAULT 'high' CHECK (confidence IN ('high', 'moderate', 'low')),
    user_override   INTEGER NOT NULL DEFAULT 0,
    override_reason TEXT,
    notes           TEXT,
    period_label    TEXT,                     -- assigned at write time based on arrival_date
                                             -- e.g. '2025-Q1' for Jan-Mar 2025
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),

    CHECK (departure_date IS NULL OR departure_date >= arrival_date)
);

CREATE TABLE family_presence (
    id                  TEXT PRIMARY KEY,
    family_member_id    TEXT NOT NULL REFERENCES family_members(id),
    country_code        TEXT NOT NULL,
    arrival_date        TEXT NOT NULL,
    departure_date      TEXT,
    source_type         TEXT NOT NULL DEFAULT 'manual' CHECK (source_type IN ('manual', 'csv', 'api', 'derived')),
    period_label        TEXT,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),

    CHECK (departure_date IS NULL OR departure_date >= arrival_date)
);


-- ============================================================
-- 3. STATUS MODIFIERS (UPDATED — period_label added)
-- ============================================================

CREATE TABLE visa_records (
    id                  TEXT PRIMARY KEY,
    country_code        TEXT NOT NULL,
    visa_type           TEXT NOT NULL,
    visa_category       TEXT NOT NULL CHECK (visa_category IN ('work', 'tourist', 'investor', 'residence', 'other')),
    valid_from          TEXT NOT NULL,
    valid_to            TEXT,
    permits_employment  INTEGER NOT NULL DEFAULT 0,
    notes               TEXT,
    period_label        TEXT,
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE tax_registrations (
    id                  TEXT PRIMARY KEY,
    country_code        TEXT NOT NULL,
    registration_type   TEXT NOT NULL CHECK (registration_type IN ('income_tax', 'social_security', 'vat', 'other')),
    tax_identifier      TEXT,
    effective_from      TEXT NOT NULL,
    effective_to        TEXT,
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deregistered', 'pending')),
    period_label        TEXT,
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE domicile_records (
    id              TEXT PRIMARY KEY,
    country_code    TEXT NOT NULL,
    domicile_type   TEXT NOT NULL CHECK (domicile_type IN ('domicile_of_origin', 'domicile_of_choice', 'deemed')),
    effective_from  TEXT NOT NULL,
    effective_to    TEXT,
    basis           TEXT,
    period_label    TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE permanent_homes (
    id                      TEXT PRIMARY KEY,
    country_code            TEXT NOT NULL,
    address_summary         TEXT,
    ownership_type          TEXT NOT NULL CHECK (ownership_type IN ('owned', 'rented', 'available')),
    available_from          TEXT NOT NULL,
    available_to            TEXT,
    continuously_available  INTEGER NOT NULL DEFAULT 1,
    notes                   TEXT,
    period_label            TEXT,
    created_at              TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE employment_records (
    id                  TEXT PRIMARY KEY,
    country_code        TEXT NOT NULL,
    employer_name       TEXT,
    employment_type     TEXT NOT NULL CHECK (employment_type IN ('employed', 'self_employed', 'director', 'govt_service')),
    effective_from      TEXT NOT NULL,
    effective_to        TEXT,
    government_service  INTEGER NOT NULL DEFAULT 0,
    notes               TEXT,
    period_label        TEXT,
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);


-- ============================================================
-- 4. RESIDENCY EVENTS (UPDATED — period_label added)
-- ============================================================

CREATE TABLE residency_events (
    id                      TEXT PRIMARY KEY,
    country_code            TEXT NOT NULL,
    event_type              TEXT NOT NULL CHECK (event_type IN ('commence_residency', 'cease_residency')),
    physical_date           TEXT NOT NULL,
    legal_effective_date    TEXT NOT NULL,
    basis                   TEXT,
    source                  TEXT NOT NULL DEFAULT 'user_asserted' CHECK (source IN ('user_asserted', 'system_derived', 'professional_advised')),
    period_label            TEXT,
    created_at              TEXT NOT NULL DEFAULT (datetime('now'))
);


-- ============================================================
-- 5. ASSERTIONS (UPDATED — period_label added)
-- ============================================================

CREATE TABLE assertions (
    id                          TEXT PRIMARY KEY,
    rule_id                     TEXT,
    treaty_tiebreaker_step_id   TEXT,
    jurisdiction_code           TEXT NOT NULL,
    tax_year                    TEXT NOT NULL,
    factor_key                  TEXT NOT NULL,
    factor_value                TEXT NOT NULL,
    user_statement              TEXT,
    supporting_evidence         TEXT,
    confidence                  TEXT NOT NULL DEFAULT 'moderate' CHECK (confidence IN ('high', 'moderate', 'low')),
    professional_reviewed       INTEGER NOT NULL DEFAULT 0,
    reviewer_notes              TEXT,
    period_label                TEXT,
    created_at                  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at                  TEXT NOT NULL DEFAULT (datetime('now'))
);


-- ============================================================
-- 6. EVALUATION RESULTS (UPDATED — period_label added)
-- ============================================================

CREATE TABLE evaluations (
    id                          TEXT PRIMARY KEY,
    jurisdiction_id             TEXT NOT NULL,
    tax_year                    TEXT NOT NULL,
    determination               TEXT NOT NULL CHECK (determination IN ('resident', 'non_resident', 'indeterminate')),
    confidence_basis            TEXT NOT NULL CHECK (confidence_basis IN ('mechanical_only', 'depends_on_assertions', 'requires_professional')),
    assertion_dependency_count  INTEGER NOT NULL DEFAULT 0,
    unresolved_rule_count       INTEGER NOT NULL DEFAULT 0,
    summary                     TEXT,
    evaluated_at                TEXT NOT NULL,
    period_label                TEXT,
    created_at                  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE rule_results (
    id                      TEXT PRIMARY KEY,
    evaluation_id           TEXT NOT NULL REFERENCES evaluations(id),
    rule_id                 TEXT NOT NULL,
    result                  TEXT NOT NULL CHECK (result IN ('pass', 'fail', 'indeterminate')),
    determination_type      TEXT NOT NULL CHECK (determination_type IN ('mechanical', 'structured_subjective', 'irreducibly_subjective')),
    explanation             TEXT,
    inputs_json             TEXT,
    threshold_comparison    TEXT,
    sensitivity_note        TEXT,
    period_label            TEXT,
    created_at              TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE rule_result_assertions (
    id              TEXT PRIMARY KEY,
    rule_result_id  TEXT NOT NULL REFERENCES rule_results(id),
    assertion_id    TEXT NOT NULL REFERENCES assertions(id),

    UNIQUE (rule_result_id, assertion_id)
);

CREATE TABLE factor_summaries (
    id                      TEXT PRIMARY KEY,
    evaluation_id           TEXT NOT NULL REFERENCES evaluations(id),
    rule_id                 TEXT NOT NULL,
    factors_json            TEXT NOT NULL,
    guidance_note           TEXT,
    professional_referral   INTEGER NOT NULL DEFAULT 1,
    period_label            TEXT,
    created_at              TEXT NOT NULL DEFAULT (datetime('now'))
);


-- ============================================================
-- 7. TREATY EVALUATIONS (UPDATED — period_label added)
-- ============================================================

CREATE TABLE treaty_evaluations (
    id                      TEXT PRIMARY KEY,
    evaluation_id           TEXT REFERENCES evaluations(id),
    treaty_id               TEXT NOT NULL,
    tax_year                TEXT NOT NULL,
    country_a_code          TEXT NOT NULL,
    country_b_code          TEXT NOT NULL,
    final_resolution        TEXT NOT NULL CHECK (final_resolution IN ('country_a', 'country_b', 'unresolved')),
    saving_clause_applied   INTEGER NOT NULL DEFAULT 0,
    saving_clause_note      TEXT,
    summary                 TEXT,
    evaluated_at            TEXT NOT NULL,
    period_label            TEXT
);

CREATE TABLE treaty_step_results (
    id                          TEXT PRIMARY KEY,
    treaty_evaluation_id        TEXT NOT NULL REFERENCES treaty_evaluations(id),
    treaty_tiebreaker_step_id   TEXT NOT NULL,
    step_order                  INTEGER NOT NULL,
    result                      TEXT NOT NULL CHECK (result IN ('resolved_to_a', 'resolved_to_b', 'inconclusive', 'not_evaluated')),
    reasoning                   TEXT,
    inputs_json                 TEXT,
    period_label                TEXT,
    created_at                  TEXT NOT NULL DEFAULT (datetime('now'))
);


-- ============================================================
-- 8. DERIVED DAY COUNTS (UPDATED — period_label added)
-- ============================================================

CREATE TABLE day_counts (
    id                      TEXT PRIMARY KEY,
    country_code            TEXT NOT NULL,
    sub_region              TEXT,
    period_type             TEXT NOT NULL CHECK (period_type IN ('calendar_year', 'rolling_12m', 'lookback_weighted', 'custom')),
    period_start            TEXT NOT NULL,
    period_end              TEXT NOT NULL,
    total_days              INTEGER NOT NULL,
    deemed_days             INTEGER DEFAULT 0,
    partial_day_adjustments INTEGER DEFAULT 0,
    calculation_method      TEXT NOT NULL DEFAULT 'midnight' CHECK (calculation_method IN ('midnight', '24hr', 'jurisdiction_specific')),
    computed_at             TEXT NOT NULL,
    period_label            TEXT
);


-- ============================================================
-- 9. RISK & PROJECTIONS (UPDATED — period_label added)
-- ============================================================

CREATE TABLE risk_alerts (
    id                      TEXT PRIMARY KEY,
    country_code            TEXT NOT NULL,
    rule_id                 TEXT,
    alert_type              TEXT NOT NULL CHECK (alert_type IN ('threshold_proximity', 'status_change', 'treaty_conflict')),
    severity                TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    message                 TEXT NOT NULL,
    days_to_threshold       INTEGER,
    projected_trigger_date  TEXT,
    acknowledged            INTEGER NOT NULL DEFAULT 0,
    period_label            TEXT,
    created_at              TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE simulations (
    id              TEXT PRIMARY KEY,
    scenario_name   TEXT NOT NULL,
    parameters_json TEXT NOT NULL,
    results_json    TEXT NOT NULL,
    period_label    TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);


-- ============================================================
-- 10. AUDIT LOG (UPDATED — period_label added)
-- ============================================================

CREATE TABLE audit_log (
    id              TEXT PRIMARY KEY,
    entity_type     TEXT NOT NULL,
    entity_id       TEXT NOT NULL,
    action          TEXT NOT NULL CHECK (action IN ('create', 'update', 'delete', 'override', 'evaluate')),
    changes_json    TEXT,
    reason          TEXT,
    period_label    TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);


-- ============================================================
-- INDEXES (UPDATED)
-- ============================================================

-- Presence
CREATE INDEX idx_presence_country ON presence_intervals(country_code);
CREATE INDEX idx_presence_dates ON presence_intervals(arrival_date, departure_date);
CREATE INDEX idx_presence_period ON presence_intervals(period_label);
CREATE INDEX idx_family_presence_member ON family_presence(family_member_id);
CREATE INDEX idx_family_presence_period ON family_presence(period_label);

-- Status modifiers
CREATE INDEX idx_visa_country ON visa_records(country_code);
CREATE INDEX idx_visa_period ON visa_records(period_label);
CREATE INDEX idx_tax_reg_period ON tax_registrations(period_label);
CREATE INDEX idx_domicile_period ON domicile_records(period_label);
CREATE INDEX idx_homes_period ON permanent_homes(period_label);
CREATE INDEX idx_employment_period ON employment_records(period_label);

-- Assertions
CREATE INDEX idx_assertions_jurisdiction ON assertions(jurisdiction_code, tax_year);
CREATE INDEX idx_assertions_period ON assertions(period_label);

-- Evaluations
CREATE INDEX idx_evaluations_jurisdiction ON evaluations(jurisdiction_id, tax_year);
CREATE INDEX idx_evaluations_period ON evaluations(period_label);
CREATE INDEX idx_rule_results_eval ON rule_results(evaluation_id);
CREATE INDEX idx_rule_results_period ON rule_results(period_label);
CREATE INDEX idx_factor_summaries_period ON factor_summaries(period_label);

-- Treaties
CREATE INDEX idx_treaty_eval_year ON treaty_evaluations(tax_year);
CREATE INDEX idx_treaty_eval_period ON treaty_evaluations(period_label);
CREATE INDEX idx_treaty_steps_period ON treaty_step_results(period_label);

-- Day counts
CREATE INDEX idx_day_counts_country ON day_counts(country_code, period_type);
CREATE INDEX idx_day_counts_period ON day_counts(period_label);

-- Risk
CREATE INDEX idx_risk_alerts_ack ON risk_alerts(acknowledged);
CREATE INDEX idx_risk_alerts_period ON risk_alerts(period_label);
CREATE INDEX idx_simulations_period ON simulations(period_label);

-- Audit
CREATE INDEX idx_audit_log_entity ON audit_log(entity_type, entity_id);
CREATE INDEX idx_audit_log_period ON audit_log(period_label);

-- Residency events
CREATE INDEX idx_residency_events_country ON residency_events(country_code);
CREATE INDEX idx_residency_events_period ON residency_events(period_label);

-- Grant tracking (new)
CREATE INDEX idx_grants_local_advisor ON _advisor_grants_local(advisor_account_id);
CREATE INDEX idx_grants_local_vault ON _advisor_grants_local(vault_type, period_label);
CREATE INDEX idx_grants_local_rolling ON _advisor_grants_local(rolling_window) WHERE rolling_window = 1;
