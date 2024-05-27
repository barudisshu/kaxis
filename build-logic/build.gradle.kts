/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

plugins {
  `kotlin-dsl` // <1>
}

repositories {
  gradlePluginPortal() // <2>
}

private val kotlinVersion = "2.0.0"
private val ktlintVersion = "12.1.0"

dependencies {
  implementation("org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlinVersion")
  implementation("org.jlleitschuh.gradle:ktlint-gradle:$ktlintVersion")
}
