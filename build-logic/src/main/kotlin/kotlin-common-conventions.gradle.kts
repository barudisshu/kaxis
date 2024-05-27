/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

import org.jetbrains.kotlin.gradle.dsl.KotlinVersion

repositories {
  gradlePluginPortal()
  mavenLocal()
  google()
  mavenCentral()
}

plugins {
  idea
  java
  id("org.jetbrains.kotlin.jvm")
  id("org.jlleitschuh.gradle.ktlint")
}

group = "io.kaxis"
version = "1.0-SNAPSHOT"

dependencies {
  // Use the Kotlin JDK standard library
  implementation(kotlin("stdlib"))
  implementation(kotlin("reflect", embeddedKotlinVersion))
  // KotlinX
  implementation(Libraries.KOTLIN_COROUTINES_CORE)
  implementation(Libraries.KOTLIN_COROUTINES_TEST)
  // Common Test
  implementation(Libraries.KOTLIN_STD_LIB)
  implementation(Libraries.JACKSON_MODULE)
  // logback
  implementation(Libraries.LOGBACK)
  // pekko
  implementation(platform(Libraries.PEKKO_DEP))

  testImplementation(kotlin("test"))

  testImplementation(Libraries.JUPITER_API)
  testImplementation(Libraries.JUPITER_PARAMS)
  testImplementation(Libraries.JUPITER_ENGINE)
  testImplementation(Libraries.JUPITER_PLATFORM)
  testImplementation(Libraries.AWAITILITY)

  // mockito
  testImplementation(Libraries.MOCKITO_CORE)
  testImplementation(Libraries.MOCKITO_JUPITER)
  testImplementation(Libraries.MOCKITO_INLINE)
  testImplementation(Libraries.MOCKK)
}

tasks {
  test {
    useJUnitPlatform()
  }
}

java {
  toolchain {
    languageVersion.set(JavaLanguageVersion.of(17))
  }
}

kotlin {
  jvmToolchain(17)
  sourceSets.all {
    languageSettings {
      languageVersion = "2.0"
    }
  }
  compilerOptions {
    languageVersion.set(KotlinVersion.KOTLIN_2_0)
    apiVersion.set(KotlinVersion.KOTLIN_2_0)
  }
}

idea {
  module.isDownloadJavadoc = true
  module.isDownloadSources = true
}

ktlint {
  android = true
  ignoreFailures = false
  enableExperimentalRules = true
  filter {
    include("**/kotlin/**")
    exclude("**/generated/**")
    exclude("**/test/**")
  }
}
