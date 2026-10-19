// SPDX-License-Identifier: GPL-3.0-or-later

import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.4.21"
    `java-library`
}

layout.buildDirectory.set(layout.projectDirectory.dir("build.nosync"))

group = "io.orlio"
version = "1.1.0"

// Fixtures are shared with the Swift package, so both languages read the same files.
val fixturesDir = layout.projectDirectory.dir("../Tests/ObscuraCryptoTests/Fixtures")

dependencies {
    // Only for reading the export manifest's JSON. Everything cryptographic is the JDK's.
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")

    testImplementation(kotlin("test-junit5"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.13.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.13.4")
    // The provider Android uses (BoringSSL), so the tests also run under it on this Mac.
    testImplementation("org.conscrypt:conscrypt-openjdk-uber:2.7.0")
}

kotlin {
    jvmToolchain(21)
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        allWarningsAsErrors.set(true)
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

// The suite runs twice: under the JDK's own providers, and with Conscrypt first.
val providers = listOf("jdk", "conscrypt")
val providerTests = providers.map { provider ->
    tasks.register<Test>("test-$provider") {
        description = "Runs the tests with the $provider crypto provider."
        group = "verification"
        testClassesDirs = sourceSets["test"].output.classesDirs
        classpath = sourceSets["test"].runtimeClasspath
        useJUnitPlatform()
        systemProperty("obscura.provider", provider)
        systemProperty("obscura.fixtures", fixturesDir.asFile.absolutePath)
        // The fixture writer is skipped unless asked for, as in the Swift package.
        System.getenv("OBSCURA_WRITE_KOTLIN_FIXTURES")?.let { environment("OBSCURA_WRITE_KOTLIN_FIXTURES", it) }
        System.getenv("OBSCURA_BENCH")?.let { environment("OBSCURA_BENCH", it) }
        testLogging {
            events("failed", "skipped")
            exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
            showStandardStreams = false
        }
    }
}

tasks.test { enabled = false }
tasks.check { dependsOn(providerTests) }
