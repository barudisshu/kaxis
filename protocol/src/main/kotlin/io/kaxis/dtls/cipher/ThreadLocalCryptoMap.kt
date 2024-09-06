/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.cipher

import java.util.concurrent.ConcurrentHashMap

/**
 * Map of algorithms and thread local crypto functions. Example:
 *
 * ```kotlin
 * val SIGNATURES = ThreadLocalCryptoMap<ThreadLocalSignature>({ algorithm -> ThreadLocalSignature(algorithm) })
 * ```
 */
open class ThreadLocalCryptoMap<CryptoFunction, TL : ThreadLocalCrypto<CryptoFunction>>(
  private val factory: Factory<TL>,
) {
  private val functions: ConcurrentHashMap<String, TL> = ConcurrentHashMap()

  /**
   * Get thread local crypto function for algorithm.
   * @param algorithm name of algorithm
   * @return thread local crypto function
   */
  operator fun get(algorithm: String): TL {
    var threadLocalCryptFunction = functions[algorithm]
    if (threadLocalCryptFunction == null) {
      val function = factory.getInstance(algorithm)
      threadLocalCryptFunction = functions.putIfAbsent(algorithm, function)
      if (threadLocalCryptFunction == null) {
        threadLocalCryptFunction = function
      }
    }
    return threadLocalCryptFunction
  }

  fun interface Factory<T> {
    fun getInstance(algorithm: String): T
  }
}
