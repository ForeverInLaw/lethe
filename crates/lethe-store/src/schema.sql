-- Lethe run-state store (SQLCipher-encrypted at the connection level).
-- Idempotency key: (run_id, platform_id). Outcomes written in a txn AFTER the
-- platform confirms; `already-gone` is recorded as 'deleted'.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS runs (
    run_id       TEXT PRIMARY KEY,
    platform     TEXT    NOT NULL,
    account      TEXT    NOT NULL,
    filter_json  TEXT    NOT NULL,
    state        TEXT    NOT NULL,   -- enumerating | preview | executing | done | aborted
    started      INTEGER NOT NULL,   -- unix secs
    finished     INTEGER
);

-- The immutable Phase-1 snapshot. This table IS the dry-run preview; Phase 2
-- acts only on rows still 'pending'.
CREATE TABLE IF NOT EXISTS items (
    run_id       TEXT    NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    platform_id  TEXT    NOT NULL,   -- stable platform id = idempotency key
    content_type TEXT    NOT NULL,
    created_at   INTEGER,
    token        TEXT,               -- opaque adapter delete-routing
    text         TEXT,               -- Phase-1 text snapshot for backup, until it ran
    media_json   TEXT    NOT NULL DEFAULT '[]', -- its files, until it ran
    platform_record TEXT,            -- the item as the platform returned it, until it ran
    backup_gap   TEXT,               -- why the backup cannot hold all of it
    file_failure TEXT,               -- unavailable | unreachable: its file was not saved, so it stayed
    delete_reach TEXT    NOT NULL DEFAULT 'everyone', -- everyone | only_for_self | nowhere
    scope_id     TEXT,               -- where the item sits on the platform, such as its chat
    state        TEXT    NOT NULL,   -- pending | protected | deleted | skipped | failed | undeletable
    attempts     INTEGER NOT NULL DEFAULT 0,
    last_error   TEXT,
    PRIMARY KEY (run_id, platform_id)
);
CREATE INDEX IF NOT EXISTS idx_items_state ON items(run_id, state);

CREATE TABLE IF NOT EXISTS receipts (
    run_id         TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
    summary_json   TEXT NOT NULL,
    public_key_hex TEXT NOT NULL,
    signature_hex  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS activity_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id  TEXT    NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    at      INTEGER NOT NULL,
    level   TEXT    NOT NULL,   -- info | warn | error
    message TEXT    NOT NULL
);
