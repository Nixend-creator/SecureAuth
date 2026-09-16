-- V3: Clear all existing sessions.
-- Sessions written by versions prior to 1.3.2 used Java LocalDateTime serialised
-- in the JVM system timezone.  If the JVM timezone differed from the MySQL server
-- timezone the stored expires_at values are incorrect and every session would
-- appear expired.  Wiping the table on upgrade forces all players to log in once;
-- from 1.3.2 onwards expires_at is computed entirely on the DB server with NOW().
TRUNCATE TABLE sa_sessions;
