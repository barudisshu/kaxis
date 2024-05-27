/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

pluginManagement {
  // Include 'plugins build' to define convention plugins.
  includeBuild("build-logic")
}

plugins {
  id("org.gradle.toolchains.foojay-resolver-convention") version "0.8.0"
}
rootProject.name = "kaxis"

include("common", "helper", "protocol", "sharding", "interoperability-tests")
