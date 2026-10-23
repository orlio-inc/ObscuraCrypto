// SPDX-License-Identifier: GPL-3.0-or-later

rootProject.name = "obscura-crypto"

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

include("cli")
