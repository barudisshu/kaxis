/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.cipher

import io.kaxis.JceProvider
import java.security.Signature

/**
 * Thread local Signature. Uses [ThreadLocal] to cache calls to [Signature.getInstance]
 */
class ThreadLocalSignature(algorithm: String) : ThreadLocalCrypto<Signature>({
  JceProvider.getEdDsaStandardAlgorithmName(algorithm, algorithm).let { Signature.getInstance(it) }
}) {
  companion object {
    /**
     * Map of thread local key signatures.
     */
    val SIGNATURES = ThreadLocalCryptoMap { ThreadLocalSignature(it) }
  }
}
