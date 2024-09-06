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
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate

/**
 * Result of certificate identity provider.
 */
class CertificateIdentityResult : HandshakeResult {
  /**
   * Private key of certificate based identity.
   */
  val privateKey: PrivateKey?

  /**
   * Public key of certificate based identity.
   */
  val publicKey: PublicKey?

  /**
   * Certificate chain of X.509 based identity.
   */
  val certificateChain: MutableList<X509Certificate>?

  /**
   * Create result with [X509Certificate].
   * @param cid connection id
   * @param privateKey private key of identity.
   * @param certificateChain certificate chain for identity
   * @throws NullPointerException if cid, private key, or chain is `null`.
   * @throws IllegalArgumentException if chain is empty.
   */
  constructor(
    cid: ConnectionId?,
    privateKey: PrivateKey?,
    certificateChain: MutableList<X509Certificate>?,
  ) : super(cid) {
    requireNotNull(privateKey) { "private Key must not be null!" }
    requireNotNull(certificateChain) { "Certificate chain must not be null!" }
    require(certificateChain.isNotEmpty()) { "Certificate chain must not be empty!" }
    this.privateKey = privateKey
    this.publicKey = certificateChain[0].publicKey
    this.certificateChain = certificateChain
  }

  /**
   * Create result with RawPublicKey.
   * @param cid connection id
   * @param privateKey private key of identity.
   * @param publicKey public key for identity.
   * @throws NullPointerException if cid, private key, or public key is `null`.
   */
  constructor(cid: ConnectionId?, privateKey: PrivateKey?, publicKey: PublicKey?) : super(cid) {
    requireNotNull(privateKey) { "private Key must not be null!" }
    requireNotNull(publicKey) { "Public key must not be null!" }
    this.privateKey = privateKey
    this.publicKey = publicKey
    this.certificateChain = null
  }

  /**
   * Create result without matching identity.
   * @param cid connection id
   * @throws NullPointerException if cid is `null`.
   */
  constructor(cid: ConnectionId?) : super(cid) {
    this.privateKey = null
    this.publicKey = null
    this.certificateChain = null
  }
}
