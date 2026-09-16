# Как получить gradle-wrapper.jar

`gradle-wrapper.jar` не включён в архив, потому что его нельзя сгенерировать без сети.  
Выбери **один** из способов:

---

## Способ 1 — через IntelliJ IDEA (рекомендуется)

Открой проект в IntelliJ → он предложит «Import Gradle Project».  
IntelliJ сам скачает wrapper jar и распакует Gradle 9.3.1.

---

## Способ 2 — через системный Gradle (если установлен)

```bat
cd C:\Users\veles\IdeaProjects\SecureAuth
gradle wrapper --gradle-version 9.3.1
```

---

## Способ 3 — скачать вручную

Скачай jar напрямую из официального репозитория Gradle:

```
https://raw.githubusercontent.com/gradle/gradle/v9.3.1/gradle/wrapper/gradle-wrapper.jar
```

Положи скачанный файл в:
```
SecureAuth\gradle\wrapper\gradle-wrapper.jar
```

---

## Способ 4 — скопировать из другого проекта

Если у тебя уже есть проект с Gradle 9.x — скопируй оттуда:
```
<другой-проект>\gradle\wrapper\gradle-wrapper.jar
→ SecureAuth\gradle\wrapper\gradle-wrapper.jar
```

После этого `.\gradlew.bat build` будет работать.
