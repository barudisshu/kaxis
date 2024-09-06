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
