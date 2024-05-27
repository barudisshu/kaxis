/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

plugins {
  id("kotlin-library-conventions")
}

configurations.all {
  exclude("junit")
}

testing {
  suites {
    // Configure the built-in test suite
    val test by getting(JvmTestSuite::class) {
      // Use JUnit Jupiter test framework
      useJUnitJupiter(Versions.JUPITER_VERSION)
    }
  }
}
