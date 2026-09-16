# Contributing to SecureAuth

## i18n Rule

**Every new user-facing string MUST be added to BOTH `lang/en.yml` AND `lang/ru.yml`.**
CI will fail if keys don't match between the two files.

## Commit Format

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add per-player language selection
fix: session not invalidated on password change
perf: reduce DB queries on login by 30%
break: renamed security.session-timeout to security.session-timeout-minutes
```

## Pull Request Checklist

- [ ] Code compiles without warnings (`-Xlint:deprecation -Xlint:unchecked`)
- [ ] All new public methods have JavaDoc
- [ ] i18n keys added to both `en.yml` and `ru.yml`
- [ ] New commands added to README Commands table
- [ ] New permissions added to `paper-plugin.yml` and README
- [ ] Tests added for new functionality
- [ ] CHANGELOG updated via Conventional Commit (not manually)

## Running Locally

```bash
./gradlew build          # Compile + test + package
./gradlew test           # Tests only
./gradlew shadowJar      # Build deployable JAR
```
