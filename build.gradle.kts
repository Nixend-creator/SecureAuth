import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar
import io.papermc.paperweight.userdev.ReobfArtifactConfiguration

plugins {
    java
    id("io.papermc.paperweight.userdev") version "2.0.0-beta.19"
    id("com.gradleup.shadow")            version "9.3.1"
    id("com.diffplug.spotless")          version "7.0.4"
    jacoco
}

group   = "dev.n1xend"
version = "1.3.0"
description = "Modern authentication plugin for Paper/Purpur 1.21.1+"

java {
    toolchain.languageVersion.set(JavaLanguageVersion.of(21))
}

// Paper 1.21.1+ ships Mojang-mapped runtime — no re-obfuscation needed
paperweight.reobfArtifactConfiguration = ReobfArtifactConfiguration.MOJANG_PRODUCTION

repositories {
    mavenCentral()
    maven("https://repo.papermc.io/repository/maven-public/")
    maven("https://jitpack.io")
    maven("https://repo.extendedclip.com/releases/")
    maven("https://repo.luckperms.net/")
}

dependencies {
    // Paper dev bundle — paperweight auto-detects Shadow and wires reobfJar → shadowJar
    paperweight.paperDevBundle("1.21.1-R0.1-SNAPSHOT")

    // ── Shaded (bundled into the fat jar) ─────────────────────────────────────
    implementation("com.zaxxer:HikariCP:7.0.2")                          // 6.3.0 → 7.0.2

    // Flyway removed — replaced with built-in MigrationManager (see database/MigrationManager.java).
    // Flyway 11.13+ has a bug in fat jars (classpath:db/callback crash), and
    // 11.12.0 doesn't support SQLite 3.49+ (flyway/flyway#4157). Zero deps is better.

    implementation("org.xerial:sqlite-jdbc:3.51.2.0")                    // 3.49.1.0 → 3.51.2.0
    implementation("com.mysql:mysql-connector-j:9.6.0") {                // 9.3.0 → 9.6.0
        // Exclude X DevAPI protobuf dependency — we don't use it
        exclude(group = "com.google.protobuf", module = "protobuf-java")
    }
    implementation("com.github.ben-manes.caffeine:caffeine:3.2.0")
    implementation("de.mkammerer:argon2-jvm:2.12")
    implementation("dev.samstevens.totp:totp:1.7.1")
    implementation("com.sun.mail:jakarta.mail:2.0.2")
    implementation("com.maxmind.geoip2:geoip2:4.3.1")

    // ── CompileOnly — provided by Paper / server at runtime ────────────────────
    compileOnly("org.slf4j:slf4j-api:2.0.17")
    compileOnly("me.clip:placeholderapi:2.11.7")
    compileOnly("com.github.MilkBowl:VaultAPI:1.7")
    compileOnly("net.luckperms:api:5.4")

    // ── Testing ────────────────────────────────────────────────────────────────
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.12.2")
    testImplementation("org.junit.jupiter:junit-jupiter-params:5.12.2")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.12.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.12.2")
    testImplementation("org.mockito:mockito-core:5.17.0")
    testImplementation("com.github.seeseemelk:MockBukkit-v1.21:3.114.0")
}

tasks {
    processResources {
        filesMatching("paper-plugin.yml") {
            expand("version" to project.version)
        }
    }

    compileJava {
        options.release.set(21)
        options.encoding = "UTF-8"
        options.compilerArgs.addAll(listOf("-Xlint:deprecation", "-Xlint:unchecked"))
    }

    compileTestJava {
        options.release.set(21)
    }

    // paperweight auto-detects Shadow and wires reobfJar → shadowJar automatically.
    // Only shadowJar itself needs configuration here.
    named<ShadowJar>("shadowJar") {
        archiveClassifier.set("")

        // mergeServiceFiles() merges all META-INF/services/* from every bundled jar
        // into single files — required for Flyway, HikariCP, MySQL driver ServiceLoader.
        // Shadow 9.x: call with explicit path pattern (no-arg overload removed in 9.x).
        mergeServiceFiles("META-INF/services")

        relocate("com.zaxxer.hikari",            "dev.n1xend.secureauth.libs.hikari")
        relocate("com.github.benmanes.caffeine", "dev.n1xend.secureauth.libs.caffeine")
        relocate("de.mkammerer.argon2",          "dev.n1xend.secureauth.libs.argon2")
        relocate("dev.samstevens.totp",          "dev.n1xend.secureauth.libs.totp")
        relocate("com.maxmind",                  "dev.n1xend.secureauth.libs.maxmind")
        relocate("org.xerial.sqlite",            "dev.n1xend.secureauth.libs.sqlite")
        relocate("jakarta.mail",                 "dev.n1xend.secureauth.libs.mail")
        relocate("com.mysql",                    "dev.n1xend.secureauth.libs.mysql")

        exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
    }

    // Rename plain jar to avoid overwriting the shadow jar in build/libs
    named<Jar>("jar") {
        archiveClassifier.set("thin")
    }

    assemble {
        dependsOn(reobfJar)
    }

    test {
        useJUnitPlatform()
        finalizedBy(jacocoTestReport)
    }

    jacocoTestReport {
        dependsOn(test)
        reports {
            xml.required.set(true)
            html.required.set(true)
        }
    }
}

spotless {
    java {
        eclipse("4.33").configFile("config/eclipse-formatter.xml")
        trimTrailingWhitespace()
        endWithNewline()
    }
}
