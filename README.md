# 🔐 SecureAuth v1.2.0

[![Release](https://img.shields.io/github/v/release/n1xend/SecureAuth)](https://github.com/n1xend/SecureAuth/releases)
[![License](https://img.shields.io/github/license/n1xend/SecureAuth)](LICENSE)
[![Paper](https://img.shields.io/badge/Paper-1.21.1+-orange)](https://papermc.io)
[![Java](https://img.shields.io/badge/Java-21-blue)](https://adoptium.net)

Современный плагин аутентификации для серверов **Paper / Purpur 1.21.1+**.  
Argon2id хэширование, TOTP 2FA, Discord-вебхуки, AntiBot, GeoIP, сессии по IP — без NMS.

---

## ✨ Возможности

| Функция | Описание |
|---|---|
| 🔐 **Регистрация / Вход** | Argon2id хэширование паролей, защита от брутфорса, кулдауны |
| 🛡️ **AntiBot** | Лимит подключений в секунду, авто-бан IP при множестве неудачных попыток |
| 🔑 **2FA (TOTP)** | Google Authenticator / Authy, QR-URI, 8 резервных кодов |
| 📱 **Сессии по IP** | Авто-вход при совпадении IP, настраиваемый TTL |
| 🌍 **GeoIP** | Блокировка/разрешение стран (MaxMind GeoLite2-Country) |
| 📧 **Email-восстановление** | Сброс пароля через SMTP |
| 🔔 **Проверка обновлений**
- Автоматическая проверка новых релизов на GitHub при старте (async, virtual thread)
- Включается/выключается флагом `update-checker.enabled` в `config.yml`
- Семантическое сравнение версий, поддержка pre-release тегов

**Discord-вебхуки** | Rich Embed уведомления по 7 событиям аутентификации |
| 🎨 **i18n** | MiniMessage, русский + английский языки из коробки |
| ⚡ **Производительность** | Java 21 Virtual Threads, Caffeine cache, HikariCP пул |
| 🔗 **Интеграции** | Vault, LuckPerms, PlaceholderAPI (9 плейсхолдеров) |
| 🌐 **Public API** | `SecureAuthApi` через `ServicesManager` для других плагинов |

---

## 📋 Требования

| Компонент | Версия |
|---|---|
| Java | **21** LTS или новее |
| Paper / Purpur | **1.21.1+** |
| MySQL *(опционально)* | 8.0+ |
| MaxMind DB *(опционально)* | GeoLite2-Country.mmdb |

---

## 🚀 Установка

```
1. Скачайте SecureAuth-1.0.0.jar со страницы релизов
2. Поместите JAR в папку plugins/
3. Запустите сервер — создастся plugins/SecureAuth/config.yml
4. Настройте config.yml (БД, язык, вебхуки и т.д.)
5. /saadmin reload  или  перезапустите сервер
```

**Для GeoIP:** скачайте `GeoLite2-Country.mmdb` с [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data),
поместите в `plugins/SecureAuth/` и установите `geoip.enabled: true`.

---

## ⚙️ Конфигурация

Полный конфиг с комментариями: [`config.yml`](src/main/resources/config.yml)

```yaml
config-version: 3
language: ru          # en | ru

database:
  type: sqlite        # sqlite | mysql

security:
  argon2:
    memory: 65536     # 64 MB — чем больше, тем безопаснее
    iterations: 3
    parallelism: 4
  max-login-attempts: 5
  ban-duration-minutes: 30
  session-timeout-minutes: 30
  session-ip-binding: true
  password-min-length: 6
  password-max-length: 64

antibot:
  enabled: true
  max-connections-per-second: 10
  ip-block-threshold: 10
  ip-block-duration-minutes: 60

two-factor:
  enabled: true
  backup-codes-count: 8

auth:
  login-timeout-seconds: 60
  blind-before-auth: true   # эффект слепоты до авторизации
  block-chat: true
  block-movement: false

# Discord-вебхуки (подробнее — раздел Webhooks ниже)
webhooks: []
```

---

## 🔔 Discord-вебхуки

Плагин отправляет rich Embed в Discord-каналы при событиях аутентификации.

**Как получить URL вебхука:**
`Channel Settings → Integrations → Webhooks → New Webhook → Copy Webhook URL`

```yaml
webhooks:
  # Основной канал — все события
  - url: "https://discord.com/api/webhooks/ID/TOKEN"
    enabled: true
    events: []      # пусто = все события

  # Канал безопасности — только подозрительная активность
  - url: "https://discord.com/api/webhooks/ID2/TOKEN2"
    enabled: true
    events: ["LOGIN_FAIL", "IP_BAN"]
```

**Доступные события:**

| Событие | Цвет | Описание |
|---|---|---|
| `REGISTER` | 🟢 зелёный | Игрок зарегистрировался |
| `LOGIN` | 🔵 синий | Успешный вход |
| `LOGOUT` | ⚫ серый | Выход из аккаунта |
| `LOGIN_FAIL` | 🔴 красный | Неверный пароль |
| `IP_BAN` | 🔴 красный | IP заблокирован AntiBot |
| `TOTP_ENABLE` | 🟢 зелёный | Игрок включил 2FA |
| `TOTP_DISABLE` | 🟡 жёлтый | Игрок отключил 2FA |

Каждый Embed содержит: ник игрока, UUID, IP-адрес, timestamp.
HTTP-запросы выполняются на виртуальных потоках — сервер не блокируется.

---

## 💬 Команды

### Игровые

| Команда | Описание |
|---|---|
| `/register <пароль> <пароль>` | Регистрация нового аккаунта |
| `/login <пароль>` | Вход в аккаунт |
| `/logout` | Выход из аккаунта |
| `/changepassword <старый> <новый>` | Смена пароля |
| `/2fa enable` | Начать настройку 2FA (QR + секрет) |
| `/2fa enable <6-значный-код>` | Подтвердить настройку 2FA |
| `/2fa disable <6-значный-код>` | Отключить 2FA |
| `/2fa <6-значный-код>` | Ввести код 2FA при входе |
| `/2fa backup` | Просмотреть резервные коды |
| `/recover <email>` | Восстановление пароля по email |

### Административные (`/saadmin`)

| Команда | Право | Описание |
|---|---|---|
| `/saadmin reload` | `secureauth.admin.reload` | Hot-reload конфига и языков |
| `/saadmin forcelogin <игрок>` | `secureauth.admin.forcelogin` | Принудительный вход |
| `/saadmin resetpassword <игрок> <пароль>` | `secureauth.admin.resetpassword` | Сброс пароля |
| `/saadmin unban <ip>` | `secureauth.admin.unban` | Снять IP-бан |
| `/saadmin listbans` | `secureauth.admin.listbans` | Список активных IP-банов с причиной и датой |
| `/saadmin history <игрок>` | `secureauth.admin.history` | История auth-событий игрока (последние 20) |
| `/saadmin stats` | `secureauth.admin.stats` | Статистика: онлайн, сессии, баны, попытки/час |
| `/saadmin debug` | `secureauth.admin.debug` | Переключить debug-режим |

---

## 🔑 Права

| Право | По умолчанию | Описание |
|---|---|---|
| `secureauth.admin` | op | Все административные команды |
| `secureauth.admin.reload` | op | `/saadmin reload` |
| `secureauth.admin.forcelogin` | op | `/saadmin forcelogin` |
| `secureauth.admin.resetpassword` | op | `/saadmin resetpassword` |
| `secureauth.admin.unban` | op | `/saadmin unban` |
| `secureauth.admin.debug` | op | `/saadmin debug` |
| `secureauth.cooldown.bypass` | op | Обход кулдаунов команд |
| `secureauth.2fa.bypass` | false | Обход обязательной 2FA |

---

## 📊 PlaceholderAPI

Требуется установленный [PlaceholderAPI](https://www.spigotmc.org/resources/placeholderapi.6245/).

| Плейсхолдер | Значения | Описание |
|---|---|---|
| `%secureauth_is_authenticated%` | `true` / `false` | Авторизован ли игрок сейчас |
| `%secureauth_is_registered%` | `true` / `false` | Зарегистрирован ли в БД |
| `%secureauth_auth_status%` | `AUTHENTICATED` / `AWAITING_2FA` / `PENDING` / `OFFLINE` | Точный статус |
| `%secureauth_has_2fa%` | `true` / `false` | Включена ли 2FA |
| `%secureauth_has_session%` | `true` / `false` | Активна ли сессия по IP |
| `%secureauth_registered_at%` | ISO дата / `N/A` | Дата регистрации |
| `%secureauth_last_login%` | ISO дата / `Never` / `N/A` | Последний вход |
| `%secureauth_last_login_ip%` | `192.168.*.*` / `N/A` | IP последнего входа (маскированный) |
| `%secureauth_failed_attempts%` | число | Неудачных попыток за текущую сессию |

---

## 🔗 Интеграции

| Плагин | Обязателен | Что даёт |
|---|---|---|
| **Vault** | Нет | Хуки экономики (баланс) |
| **LuckPerms** | Нет | Запрос группы, временные пермишены |
| **PlaceholderAPI** | Нет | 9 плейсхолдеров (см. выше) |

Все интеграции — **soft-depend**: плагин работает без них.

---

## 🌐 Public API

Для других плагинов через Bukkit `ServicesManager`:

```java
SecureAuthApi api = getServer().getServicesManager()
    .load(SecureAuthApi.class);

if (api != null) {
    boolean authed = api.auth().isAuthenticated(player.getUniqueId());
    boolean has2fa = api.totp().isEnabled(player.getUniqueId());

    // Слушать события аутентификации
    api.auth().addListener((uuid, from, to) -> {
        if (to == AuthApi.Stage.AUTHENTICATED) {
            // игрок вошёл
        }
    });
}
```

**Доступные под-API:**

| API | Ключевые методы |
|---|---|
| `SecureAuthApi` | `version()`, `auth()`, `session()`, `totp()`, `antibot()` |
| `AuthApi` | `isAuthenticated()`, `getStage()`, `addListener()` |
| `SessionApi` | `hasValidSession()`, `invalidate()` |
| `TotpApi` | `isEnabled()` |
| `AntiBotApi` | `isBanned()`, `ban()`, `unban()` |

---

## 🗄️ База данных

**SQLite** (по умолчанию) — файл `plugins/SecureAuth/data.db`, настройка не нужна.

**MySQL:**
```yaml
database:
  type: mysql
  mysql:
    host: localhost
    port: 3306
    database: secureauth
    username: root
    password: "your_password"
    pool-size: 10
```

Схема создаётся автоматически через встроенный `MigrationManager`.
Таблицы: `sa_players`, `sa_sessions`, `sa_totp`, `sa_ip_bans`, `sa_login_attempts`, `sa_schema_version`.

---

## 🌍 Языки

| Язык | Файл | Статус |
|---|---|---|
| English | `lang/en.yml` | ✅ Полный |
| Русский | `lang/ru.yml` | ✅ Полный |

Добавить язык: скопируйте `en.yml`, переведите, укажите `language: xx` в конфиге.
Все сообщения поддерживают [MiniMessage](https://docs.advntr.dev/minimessage/format.html) форматирование.

---

## 🔒 Заметки о безопасности

**Argon2id** — рекомендованный алгоритм хэширования паролей (Password Hashing Competition 2015). Параметры памяти и итераций настраиваются под мощность сервера. Увеличьте `memory` на мощных серверах для большей стойкости.

**Сессии по IP** — авто-вход при совпадении IP в рамках TTL. При смене IP сессия не работает. Отключите `session-ip-binding: false` если ваши игроки часто меняют IP (мобильный интернет).

**AntiBot** — работает в двух режимах: rate-gate на подключения в секунду и счётчик неудачных попыток на IP. Оба независимы и дополняют друг друга.

---

## 📄 Лицензия

MIT © [n1xend](https://github.com/n1xend)
