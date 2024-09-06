/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

object Libraries {
  // Classpath Gradle Plugin
  const val CLASSPATH_KOTLIN_GRADLE =
    "org.jetbrains.kotlin:kotlin-gradle-plugin:${Versions.KOTLIN_VERSION}"

  // Core
  const val KOTLIN_STD_LIB =
    "org.jetbrains.kotlin:kotlin-stdlib:${Versions.KOTLIN_VERSION}"

  // Coroutines
  const val KOTLIN_COROUTINES_CORE =
    "org.jetbrains.kotlinx:kotlinx-coroutines-core:${Versions.KOTLIN_COROUTINES_VERSION}"
  const val KOTLIN_COROUTINES_TEST =
    "org.jetbrains.kotlinx:kotlinx-coroutines-test:${Versions.KOTLIN_COROUTINES_VERSION}"

  // json object
  const val JACKSON_MODULE = "com.fasterxml.jackson.module:jackson-module-kotlin:${Versions.JACKSON_MODULE_VERSION}"

  // log4j2
  const val LOGBACK = "ch.qos.logback:logback-classic:${Versions.LOGBACK_VERSION}"

  // bouncycastle
  const val BCPKIX = "org.bouncycastle:bcpkix-jdk18on:${Versions.BOUNCYCASTLE_VERSION}"
  const val BCTLS = "org.bouncycastle:bctls-jdk18on:${Versions.BOUNCYCASTLE_VERSION}"

  // pekko
  const val PEKKO_DEP = "org.apache.pekko:pekko-bom_${Versions.SCALA_VERSION}:${Versions.PEKKO_VERSION}"
  const val PEKKO_ACTOR = "org.apache.pekko:pekko-actor-typed_${Versions.SCALA_VERSION}"
  const val PEKKO_SLF4J = "org.apache.pekko:pekko-slf4j_${Versions.SCALA_VERSION}"
  const val PEKKO_CLUSTER = "org.apache.pekko:pekko-cluster-typed_${Versions.SCALA_VERSION}"
  const val PEKKO_CLUSTER_SHARDING = "org.apache.pekko:pekko-cluster-sharding-typed_${Versions.SCALA_VERSION}"
  const val PEKKO_STREAM = "org.apache.pekko:pekko-stream_${Versions.SCALA_VERSION}"
  const val PEKKO_STREAM_TESTKIT = "org.apache.pekko:pekko-stream-testkit_${Versions.SCALA_VERSION}"
  const val PEKKO_SERIALIZATION = "org.apache.pekko:pekko-serialization-jackson_${Versions.SCALA_VERSION}"
  const val PEKKO_PERSISTENCE = "org.apache.pekko:pekko-persistence-typed_${Versions.SCALA_VERSION}"
  const val PEKKO_TESTKIT = "org.apache.pekko:pekko-actor-testkit-typed_${Versions.SCALA_VERSION}"
  const val PEKKO_MULTI_NODE_TESTKIT = "org.apache.pekko:pekko-multi-node-testkit_${Versions.SCALA_VERSION}"
  const val PEKKO_PERSISTENCE_TESTKIT = "org.apache.pekko:pekko-persistence-testkit_${Versions.SCALA_VERSION}"
  const val PEKKO_PERSISTENCE_CASSANDRA = "org.apache.pekko:pekko-persistence-cassandra_${Versions.SCALA_VERSION}"
  const val PEKKO_MANAGEMENT =
    "org.apache.pekko:pekko-management_${Versions.SCALA_VERSION}:${Versions.PEKKO_MANAGEMENT_VERSION}"
  const val PEKKO_MANAGEMENT_HTTP =
    "org.apache.pekko:pekko-management-cluster-http_${Versions.SCALA_VERSION}:${Versions.PEKKO_MANAGEMENT_VERSION}"

  const val LETTUCE = "io.lettuce:lettuce-core:6.3.0.RELEASE"
  const val JAVA8_COMPAT = "org.scala-lang.modules:scala-java8-compat_${Versions.SCALA_VERSION}:1.0.2"

  // test
  const val JUPITER_API = "org.junit.jupiter:junit-jupiter-api:${Versions.JUPITER_VERSION}"
  const val JUPITER_PARAMS = "org.junit.jupiter:junit-jupiter-params:${Versions.JUPITER_VERSION}"
  const val JUPITER_ENGINE = "org.junit.jupiter:junit-jupiter-engine:${Versions.JUPITER_VERSION}"
  const val JUPITER_PLATFORM = "org.junit.platform:junit-platform-runner:${Versions.PLATFORM_VERSION}"

  // Awaitility
  const val AWAITILITY = "org.awaitility:awaitility:${Versions.AWAITILITY}"

  // mockito
  const val MOCKITO_CORE = "org.mockito:mockito-core:${Versions.MOCKITO_VERSION}"
  const val MOCKITO_JUPITER = "org.mockito:mockito-junit-jupiter:${Versions.MOCKITO_VERSION}"
  const val MOCKITO_INLINE = "org.mockito:mockito-inline:${Versions.MOCKITO_VERSION}"

  const val MOCKK = "io.mockk:mockk:${Versions.MOCKK_VERSION}"
}
