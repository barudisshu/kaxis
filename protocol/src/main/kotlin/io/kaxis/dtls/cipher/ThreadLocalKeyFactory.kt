/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.cipher

import io.kaxis.JceProvider
import java.security.KeyFactory

/**
 * Thread local KeyFactory. Uses [ThreadLocal] to cache calls to [KeyFactory.getInstance].
 */
class ThreadLocalKeyFactory(algorithm: String) : ThreadLocalCrypto<KeyFactory>({
  JceProvider.getEdDsaStandardAlgorithmName(algorithm, algorithm).let { KeyFactory.getInstance(it) }
}) {
  companion object {
    /**
     * Map of thread local key factories.
     */
    val KEY_FACTORIES = ThreadLocalCryptoMap { ThreadLocalKeyFactory(it) }
  }
}
