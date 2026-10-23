// SPDX-License-Identifier: GPL-3.0-or-later

import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
    application
}

layout.buildDirectory.set(layout.projectDirectory.dir("build.nosync"))

group = "io.orlio"
version = rootProject.version

dependencies {
    implementation(rootProject)
    // The folder file is JSON, as in the Swift tool.
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")

    testImplementation(kotlin("test-junit5"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.13.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.13.4")
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

application {
    mainClass.set("io.orlio.obscuracrypto.cli.MainKt")
    applicationName = "obscura"
}

tasks.test {
    useJUnitPlatform()
    systemProperty("obscura.fixtures", rootProject.layout.projectDirectory.dir("../Tests/ObscuraCryptoTests/Fixtures").asFile.absolutePath)
    testLogging {
        events("failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
