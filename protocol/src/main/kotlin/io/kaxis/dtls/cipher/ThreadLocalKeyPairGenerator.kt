/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.cipher

import io.kaxis.JceProvider
import java.security.KeyPairGenerator

/**
 * Thread local KeyPairGenerator. Uses [ThreadLocal] to cache calls to [KeyPairGenerator.getInstance].
 */
class ThreadLocalKeyPairGenerator(algorithm: String) : ThreadLocalCrypto<KeyPairGenerator>({
  JceProvider.getEdDsaStandardAlgorithmName(algorithm, algorithm).let { KeyPairGenerator.getInstance(it) }
})
