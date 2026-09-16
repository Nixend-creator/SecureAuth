# Сборка SecureAuth

## Требования
- JDK 21+
- Интернет (первая сборка скачивает Gradle и зависимости ~150 MB)
- gradle-wrapper.jar (см. ниже)

## Получить gradle-wrapper.jar

**Способ 1** — скачать вручную:
```
https://raw.githubusercontent.com/gradle/gradle/v9.0.0/gradle/wrapper/gradle-wrapper.jar
```
Положить в: `gradle/wrapper/gradle-wrapper.jar`

**Способ 2** — через системный Gradle (если установлен):
```cmd
gradle wrapper --gradle-version 9.0.0
```

## Сборка

```cmd
:: ВАЖНО: всегда делать clean перед сборкой после смены build.gradle.kts
gradlew.bat clean shadowJar
```

Результат: `build\libs\SecureAuth-1.0.0-rc.3.jar` (~8–12 МБ)

## Почему shadowJar, не build?

Задача `build` включает тесты (MockBukkit требует Paper API который нет локально).
`shadowJar` собирает только fat jar без запуска тестов.

## Что должно быть в build/libs/

| Файл | Размер | Назначение |
|------|--------|------------|
| SecureAuth-1.0.0-rc.3.jar | ~8–12 МБ | ✅ Плагин для сервера |

Если видишь `dev-all` или файл меньше 1 МБ — сделай `gradlew.bat clean` и повтори.
