# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes    |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities via GitHub Issues.**

Send a private report to: **security@nixend.dev** (or use GitHub's private vulnerability reporting).

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive an acknowledgement within 48 hours.
Vulnerabilities confirmed as valid will be patched within 14 days.

## Security Practices

### Cryptography & Storage
- Passwords hashed with **Argon2id** (memory=64MB, iterations=3) — winner of the Password Hashing Competition
- TOTP codes/backup codes checked with **constant-time comparison** to avoid timing side channels
- All SQL uses **PreparedStatement** — no SQL injection possible
- All bundled libraries are **relocated** in shadowJar
- Dependencies scanned with **Trivy** on every CI build

### Authentication & Session Integrity
- **Persistent, cross-session lockout**: `max-login-attempts` survives disconnect/reconnect (backed by `sa_audit_log`, not an in-memory counter alone) — automatically clears on a legitimate password change/reset
- **TOTP replay protection**: a code is only valid for its time-bucket the first time it's used, closing the gap exploited by real-time OTP-relay phishing
- Sessions are **IP-bound by default**, with a two-layer ban/GeoIP re-check specifically to handle reverse proxies (e.g. BungeeCord-style setups) that only expose the real client IP after `PlayerJoinEvent`
- Password recovery (`/recover`) **never accepts an email as a command argument** — the reset token is only ever sent to an address previously linked and verified via `/setemail`, which itself requires already being authenticated. This closes a class of bug where anyone controlling a Minecraft session (not necessarily the account's real owner) could redirect password recovery to an address they control
- Race conditions in TOTP setup, backup-code verification/regeneration, and login cooldowns are closed via per-account locking and atomic tracking (see CHANGELOG 1.4.16–1.4.18, 1.4.7)

### Output & Injection Safety
- Every value substituted into a MiniMessage message template (email addresses, IPs, ban reasons) is escaped via `MiniMessage.escapeTags()` before rendering — untrusted input can never inject a live `<click:run_command:'...'>` tag that could trick a privileged viewer (e.g. staff reviewing ban records) into executing a disguised command
- Passwords, new passwords, and 2FA codes are automatically redacted from console output and log files via a Log4j2 filter, even for `/login`, `/register`, etc. typed without the leading `/` directly into chat
- Discord webhook URLs (themselves bearer credentials) are masked before being logged

### Database Portability
- IP banning and 2FA enrollment are tested against **both SQLite and MySQL/MariaDB** — database-specific upsert syntax caused both features to be completely non-functional on MySQL in past releases if only tested against SQLite; CI should cover both backends
- `database.mysql.use-ssl: true` is available and recommended whenever the database server is not on the same host as the game server — without it, credentials and session data cross the network in plaintext

### Public API
- `SessionApi`/`AntiBotApi` document clearly which methods block on JDBC I/O and provide `*Async` (`CompletableFuture`-returning) alternatives for callers on the main thread

---

For the detailed history of every security-relevant fix (with root-cause writeups), see [`CHANGELOG.md`](CHANGELOG.md) starting from version 1.4.0 — the project underwent a 20+ round independent security audit covering the entire codebase.
