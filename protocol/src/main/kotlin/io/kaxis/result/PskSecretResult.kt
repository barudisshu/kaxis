/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.result

import io.kaxis.dtls.ConnectionId
import io.kaxis.dtls.PskPublicInformation
import javax.crypto.SecretKey

/**
 * Result of PSK secret. On success contains the secret and a normalized psk identity. If failed, only psk identity is
 * contained. The secret must either be a master secret (algorithm "MAC"), or a PSK secret key (algorithm "PSK").
 */
class PskSecretResult : HandshakeResult {
  companion object {
    val ALGORITHM_PSK = "PSK"
    val ALGORITHM_MAC = "MAC"
  }

  /**
   * PSK identity. On success, the identity is [PskPublicInformation.normalize]d.
   */
  val pskIdentity: PskPublicInformation

  /**
   * Master secret (algorithm "MAC"), or PSK secret key (algorithm "PSK").
   */
  val secret: SecretKey?

  /**
   * Create result with custom argument for [ApplicationLevelInfoSupplier].
   * @param cid connection id
   * @param pskIdentity PSK identity
   * @param secret secret, `null`, if generation failed. Algorithm must be "MAC" or "PSK".
   * @throws IllegalArgumentException if algorithm is neither "MAC" nor "PSK"
   * @throws NullPointerException if cid or pskIdentity is `null`
   */
  constructor(cid: ConnectionId?, pskIdentity: PskPublicInformation, secret: SecretKey?) : super(cid) {
    if (secret != null) {
      val algorithm = secret.algorithm
      require(ALGORITHM_MAC == algorithm || ALGORITHM_PSK == algorithm) {
        "Secret must be either MAC for master secret, or PSK for secret key, but not $algorithm!"
      }
    }
    this.pskIdentity = pskIdentity
    this.secret = secret
  }
}
