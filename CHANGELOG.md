# SecureAuth — Changelog

Формат: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Версионирование: [Semantic Versioning](https://semver.org/).

---

## [1.3.0] — 2026-02-27

### Аудит кода — полная техническая очистка

#### Импорты

- `AuthListener.java` — `AuditEvent`, `WebhookService` перемещены перед `org.bukkit.*` (нарушение алфавитного порядка dev.* → org.* → java.*)
- `PluginConfig.java` — `dev.n1xend.secureauth.webhook.WebhookTarget` перемещён перед `org.bukkit.*`; добавлен явный `import java.util.Collections` вместо полного имени `java.util.Collections.emptyList()` в теле метода
- `TotpService.java` — wildcard `dev.samstevens.totp.code.*` заменён на явные `CodeGenerator`, `DefaultCodeGenerator`, `HashingAlgorithm`; wildcard `java.util.*` заменён на `ArrayList`, `List`, `UUID`
- `MigrationManager.java` — удалён `import java.util.stream.Collectors`; `reader.lines().collect(Collectors.joining("\n"))` заменён на прямой `readLine()` + `StringBuilder`

#### Javadoc

- `SecureAuthPlugin.java` — Javadoc для `reloadWebhookService()` ошибочно стоял перед `getUpdateChecker()` и не был связан ни с каким методом; перемещён на правильный метод с расширенным описанием

#### Стиль и форматирование

- `AdminCommand.java` — убрана двойная пустая строка между `handleDebug()` и `handleHistory()`
- `AuthListener.onPlayerQuit()` — убраны избыточные поясняющие комментарии к строкам audit/webhook (код самодокументирован)

#### GitHub Actions

- `ci.yml`, `codeql.yml` — step name `Set up Java 25` исправлен на `Set up Java 21` (только описание шага; фактическая версия `java-version: '21'` была верной)

#### Причина, почему `.github/` не загрузился на GitHub

Папка `.github/` начинается с точки — некоторые git GUI-клиенты (IntelliJ IDEA, GitHub Desktop) и файловые менеджеры Windows скрывают такие папки и не включают их в первоначальный коммит.

**Решение** — выполнить в терминале:
```bash
git add .github/ --force
git commit -m "ci: add GitHub Actions workflows"
git push origin main
```
После этого создание тега `v1.3.0` запустит `release.yml` и создаст релиз автоматически.

**Обновление с 1.2.0**: только JAR, config и lang-файлы не изменились.

---

## [1.2.0] — 2026-02-26

### Добавлено

**Проверка обновлений** (`UpdateChecker`)
- При старте плагин асинхронно проверяет последний релиз на GitHub (`api.github.com/repos/Nixend-creator/SecureAuth/releases/latest`)
- При наличии новой версии выводит предупреждение в консоль с ссылкой на релиз
- Управляется флагом `update-checker.enabled: true/false` в `config.yml`
- Семантическое сравнение версий: `MAJOR.MINOR.PATCH`, корректно обрабатывает pre-release суффиксы (`-rc.1`, `-beta`)
- Нулевая нагрузка на main thread — virtual thread, 5-секундный таймаут

### Исправлено

- **Вебхуки после `/saadmin reload`** — `WebhookService` теперь включён в цикл hot-reload: при каждом `/saadmin reload` старый executor корректно завершается и создаётся новый с актуальными targets из config. Раньше изменения в секции `webhooks:` не вступали в силу без рестарта сервера
- **QR-код для 2FA** — `otpauth://` URI заменён кликабельной ссылкой на QR-изображение через `api.qrserver.com`. Игрок кликает в чате → открывает браузер → сканирует QR телефоном
- **lang файлы** — `lang-version` поднят до `3`; при старте с версией `1.2.0` внешние lang-файлы версии `< 3` автоматически перезаписываются из JAR

### Технические изменения

- `config-version` поднят до `3` — добавлена секция `update-checker`
- `ModuleManager` теперь принимает `SecureAuthPlugin` и управляет lifecycle `WebhookService`
- `TotpSetupData` record расширен полем `qrImageUrl` (URL на PNG через QR Server API)

**Обновление с 1.1.0**

Заменить JAR, рестарт. Config-version изменён с 2 на 3 — Bukkit выдаст предупреждение о несовпадении; обновите `config-version: 3` в своём `config.yml` или удалите файл для генерации нового.

---

## [1.1.0] — 2026-02-26

### Добавлено

**Аудит-лог** (`sa_audit_log`)
- Новая таблица `sa_audit_log` — запись всех auth-событий: тип, UUID, ник, IP, детали, timestamp
- 11 типов событий: `REGISTER`, `LOGIN`, `LOGIN_FAIL`, `LOGOUT`, `PASSWORD_CHANGE`, `PASSWORD_RESET`, `TOTP_ENABLE`, `TOTP_DISABLE`, `SESSION_RESTORE`, `FORCE_LOGIN`, `IP_BAN`
- Автоматическое pruning: хранится до 200 записей на игрока (старые удаляются)
- Миграция V2 применяется автоматически при первом запуске

**Новые admin-команды**
- `/saadmin history <игрок>` — последние 20 событий аудита: кто, когда, откуда
- `/saadmin stats` — статистика сервера: онлайн/всего игроков, активные сессии, IP-баны, неудачные попытки за час, регистрации за 24ч
- `/saadmin listbans` — список всех активных IP-банов с причиной и датой истечения

**Инфраструктура**
- `AuditLogService` — новый сервис, пишет события на virtual threads (fire-and-forget)
- `DatabaseManager.isMysql()` — новый метод для dialect-aware запросов

### Исправлено

- **2FA**: `DefaultCodeVerifier` теперь допускает ±1 период (±30 секунд) — исправляет сбои из-за расхождения часов между сервером и телефоном
- **lang файлы**: `LanguageManager` теперь сравнивает `lang-version` внешнего файла с bundled; при устаревшей версии автоматически перезаписывает файл из JAR — исправляет отображение `{placeholder}` буквально после обновления плагина
- **lang fallback**: если внешний файл не содержит ключ — берётся из bundled JAR вместо `[MISSING: key]`
- **Email / SMTP**: добавлен `mail.smtp.starttls.required=true` и `ssl.protocols=TLSv1.2 TLSv1.3` — исправляет отправку через Gmail с app password
- **Вебхуки**: `buildWebhooks()` теперь защищён от некорректного YAML-формата (например `webhooks: [events]`); логирует предупреждение с правильным примером формата
- Аудит событий в `AdminCommand`: `FORCE_LOGIN` и `PASSWORD_RESET` теперь записываются в аудит-лог

### Технические заметки

**Обновление с 1.0.0**

JAR-файл заменить, рестарт сервера. При первом запуске:
- V2 миграция создаёт `sa_audit_log` автоматически
- Если `lang-version` в `lang/ru.yml` или `lang/en.yml` < 2, файл перезаписывается из JAR (ваши кастомные переводы необходимо добавить заново)

**Конфиг вебхуков** — правильный формат:
```yaml
webhooks:
  - url: "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
    enabled: true
    events: []   # пусто = все события
```
Формат `webhooks: [events]` **некорректен** и будет проигнорирован с предупреждением.

---

## [1.0.0] — 2026-02-26

Первый стабильный релиз. Выход из release-candidate фазы.

### Добавлено

**Аутентификация**
- `/register <пароль> <пароль>` — регистрация с Argon2id хэшированием
- `/login <пароль>` — вход с защитой от брутфорса
- `/logout` — инвалидация сессии
- `/changepassword <старый> <новый>` — смена пароля с проверкой текущего
- `/recover <email>` — восстановление пароля через SMTP (требует настройки email)
- После `/register` требуется отдельный `/login` — игрок явно подтверждает пароль

**2FA (TOTP)**
- `/2fa enable` — генерация секрета + QR-URI для Google Authenticator / Authy
- `/2fa enable <код>` — подтверждение настройки, генерация 8 резервных кодов
- `/2fa disable <код>` — отключение с проверкой кода
- `/2fa <код>` — ввод кода в процессе входа
- `/2fa backup` — просмотр резервных кодов

**Безопасность**
- Argon2id (64 MB / 3 итерации / 4 потока, настраивается)
- Максимум попыток входа + авто-бан по IP на настраиваемое время
- AntiBot: лимит подключений в секунду + авто-блокировка IP
- Сессии по IP с настраиваемым TTL (авто-вход при совпадении IP)
- Политика паролей: минимальная и максимальная длина
- Rate limiting: скользящее окно на каждую команду
- Per-command кулдауны
- Эффект слепоты до авторизации (опционально)
- Блокировка чата и движения до авторизации (опционально)
- GeoIP: блокировка/разрешение стран (MaxMind GeoLite2-Country)

**Discord-вебхуки** *(новое в 1.0.0)*
- Rich Embed формат с цветовой кодировкой по типу события
- 7 событий: `REGISTER`, `LOGIN`, `LOGOUT`, `LOGIN_FAIL`, `IP_BAN`, `TOTP_ENABLE`, `TOTP_DISABLE`
- Фильтр событий на каждый endpoint (пустой список = все события)
- Поддержка нескольких webhook URL одновременно
- Виртуальные потоки — нулевая блокировка main thread
- Graceful shutdown: ожидание in-flight запросов до 5 секунд

**Интеграции (soft-depend)**
- Vault — хуки экономики
- LuckPerms — запрос основной группы, временные пермишены. Lazy classloading: классы LP загружаются только при наличии плагина
- PlaceholderAPI — 9 плейсхолдеров: `is_authenticated`, `is_registered`, `auth_status`, `has_2fa`, `has_session`, `registered_at`, `last_login`, `last_login_ip`, `failed_attempts`

**Администрирование** (`/saadmin`)
- `reload` — горячая перезагрузка конфига и языков без рестарта
- `forcelogin <игрок>` — принудительный вход
- `resetpassword <игрок> <пароль>` — сброс пароля
- `unban <ip>` — снятие IP-бана
- `debug` — переключение режима отладки

**База данных**
- SQLite (по умолчанию, без настройки) и MySQL/MariaDB
- HikariCP 7.0.2 connection pool
- Встроенный `MigrationManager` — нулевые зависимости (заменил Flyway)
- Самовосстановление: обнаруживает и исправляет состояние "запись есть, таблицы нет"

**Public API** (через `ServicesManager`)
- `SecureAuthApi`, `AuthApi`, `SessionApi`, `TotpApi`, `AntiBotApi`
- Подписка на события смены стадии аутентификации через `AuthApi.addListener()`

**Инфраструктура**
- Java 21 Virtual Threads для всего I/O
- Caffeine cache для данных игроков и сессий
- Startup timer с временем каждого этапа
- Graceful shutdown: сброс активных сессий в БД
- Zero NMS — только Paper API
- Горячая перезагрузка конфига и языков без пересоздания пула БД

---

### Изменено

- После `/register` больше нет авто-авторизации — требуется явный `/login`
- Сообщение `register.success` обновлено: явно просит выполнить `/login`

---

### История Release Candidates

| Версия | Ключевые изменения |
|---|---|
| rc.1 | Первая реализация — полный набор функций |
| rc.2 | Downgrade Java 25 → 21; Gradle 9 + Shadow 8 |
| rc.3 | Исправлена сборка: paperweight + Shadow wiring; HikariCP в fat jar |
| rc.4 | Восстановлен paperweight 2.0.0-beta.19; обновлены версии зависимостей |
| rc.5 | Исправлена неоднозначная перегрузка `callbackLocations()` в Flyway 12.x |
| rc.6 | Shadow 9.3.1 — поддержка `invokedynamic` (лямбды Java 21) |
| rc.7 | Flyway downgrade до 11.12.0; исправлена передача classloader |
| rc.8 | Flyway удалён; добавлен собственный `MigrationManager` |
| rc.9 | Lazy classloading в `LuckPermsIntegration` (NoClassDefFoundError) |
| rc.10 | Переписан SQL-парсер в `MigrationManager`; самовосстановление миграций |
| rc.11 | Исправлен путь к ресурсу миграции (`V1__init.sql`) |
| **1.0.0** | Вебхуки Discord; исправлен дублирующий `/login` после регистрации; config v2 |

---

### Технические заметки

**Почему не Flyway?**
Flyway 11.13+ крашится в fat jar с `Unknown prefix for location: classpath:db/callback`
(flyway/flyway#4157). Downgrade до 11.12.0 избегал этого, но не поддерживал SQLite 3.49+.
Собственный `MigrationManager` — 150 строк, нулевые зависимости, полностью надёжен.

**Paperweight + Shadow**
`paperweight-userdev` 2.0.0-beta.19 автоматически обнаруживает Shadow и прокидывает
`reobfJar → shadowJar`. Ручная установка `inputJar` не нужна и ломает сборку.
Shadow 9.3.1 обязателен для поддержки Java 21 лямбд (ASM invokedynamic).

**config-version: 2**
Версия конфига повышена в 1.0.0 (добавлен раздел `webhooks:`).
При обновлении с rc.11: удалите `config.yml` или добавьте секцию вручную.
