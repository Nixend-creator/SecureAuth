-- V3: Clear all existing sessions (see mysql/V3 for rationale).
-- SQLite does not support TRUNCATE; DELETE FROM is equivalent.
DELETE FROM sa_sessions;
