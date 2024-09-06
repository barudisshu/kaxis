/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

import com.github.jengelman.gradle.plugins.shadow.transformers.AppendingTransformer

plugins {
  id("kotlin-application-conventions")
  id("com.github.johnrengelman.shadow") version ("8.1.1")
}

dependencies {
  implementation(project(":common"))
  implementation(project(":helper"))
  implementation(project(":protocol"))

  implementation(Libraries.PEKKO_ACTOR)
  implementation(Libraries.PEKKO_SLF4J)
  implementation(Libraries.PEKKO_CLUSTER)
  implementation(Libraries.PEKKO_CLUSTER_SHARDING)
  implementation(Libraries.PEKKO_STREAM)
  implementation(Libraries.PEKKO_STREAM_TESTKIT)
  implementation(Libraries.PEKKO_SERIALIZATION)
  implementation(Libraries.PEKKO_PERSISTENCE)
  implementation(Libraries.PEKKO_MANAGEMENT)
  implementation(Libraries.PEKKO_MANAGEMENT_HTTP)
  implementation(Libraries.LETTUCE)
  implementation(Libraries.JAVA8_COMPAT)

  testImplementation(Libraries.PEKKO_TESTKIT)
  testImplementation(Libraries.PEKKO_PERSISTENCE_TESTKIT)

  // bouncycastle
  testImplementation(Libraries.BCPKIX)
  testImplementation(Libraries.BCTLS)
}

application {
  mainClass.set("io.kaxis.Application")
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
tasks {
//  test {
//    useJUnit()
//  }
  shadowJar {
    archiveFileName.set("kaxis.jar")
    destinationDirectory.set(file("./build/libs"))

    val newTransformer = AppendingTransformer()
    newTransformer.resource = "reference.conf"
    transformers.add(newTransformer)
  }
}
