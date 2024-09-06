/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.result

import io.kaxis.dtls.ConnectionId
import io.kaxis.exception.HandshakeException
import java.security.PublicKey
import java.security.cert.CertPath

/**
 * Result of certificate verification. On success contains the resulting certificate path for X.509, or the public
 * key for RPK.
 */
class CertificateVerificationResult : HandshakeResult {
  /**
   * Verified the resulting certificate path for X.509. If [NewAdvancedCertificateVerifier.verifyCertificate] is called
   * with `truncateCertificatePath` set to `true`, the certificate path of the received certificate message is
   * truncated to one of the trust anchors. Maybe contain an empty path if the received certificate message
   * doesn't contain a certificate.
   */
  val certificatePath: CertPath?

  /**
   * Verified public key for RPK.
   */
  val publicKey: PublicKey?

  /**
   * handshake exception.
   */
  val exception: HandshakeException?

  /**
   * Create result.
   *
   * @param cid connection id.
   * @param certificatePath verified certificate path for X.509. `null`, if certificate path could not be verified.
   * @throws NullPointerException if cid is `null`
   */
  constructor(cid: ConnectionId?, certificatePath: CertPath?) : super(cid) {
    this.certificatePath = certificatePath
    this.publicKey = null
    this.exception = null
  }

  /**
   * Create result.
   * @param cid connection id
   * @param publicKey verified public key for RPK. `null`, if public key could not be verified.
   * @throws NullPointerException if cid is `null`.
   */
  constructor(cid: ConnectionId?, publicKey: PublicKey?) : super(cid) {
    this.certificatePath = null
    this.publicKey = publicKey
    this.exception = null
  }

  /**
   * Create result.
   * @param cid connection id
   * @param exception handshake exception.
   * @throws NullPointerException if cid or exception is `null`
   */
  constructor(cid: ConnectionId?, exception: HandshakeException?) : super(cid) {
    requireNotNull(exception) { "exception must not be null!" }
    this.certificatePath = null
    this.publicKey = null
    this.exception = exception
  }
}
