/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
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
