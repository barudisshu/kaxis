/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.message.handshake

import io.kaxis.dtls.CertificateType
import io.kaxis.dtls.cipher.CipherSuite

/**
 * Handshake parameter. Parameter which are defined by exchanged handshake messages and are used to decode
 * other handshake messages.
 * @param keyExchangeAlgorithm the key exchange algorithm
 * @param certificateType the certificate type
 */
class HandshakeParameter(
  val keyExchangeAlgorithm: CipherSuite.KeyExchangeAlgorithm,
  val certificateType: CertificateType,
) {
  override fun toString(): String {
    return "KeyExgAl=$keyExchangeAlgorithm, cert.type=$certificateType"
  }
}
