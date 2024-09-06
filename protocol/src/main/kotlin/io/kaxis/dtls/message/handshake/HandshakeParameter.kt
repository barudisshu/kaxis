/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
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
