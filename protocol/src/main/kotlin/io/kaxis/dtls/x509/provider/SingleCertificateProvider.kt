/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.x509.provider

import io.kaxis.dtls.*
import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.dtls.cipher.XECDHECryptography
import io.kaxis.dtls.x509.CertificateConfigurationHelper
import io.kaxis.dtls.x509.CertificateProvider
import io.kaxis.dtls.x509.ConfigurationHelperSetup
import io.kaxis.result.CertificateIdentityResult
import io.kaxis.util.SslContextUtil
import org.slf4j.LoggerFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.*
import javax.security.auth.x500.X500Principal
import kotlin.collections.ArrayList

/**
 * Certificate identity provider based on a single certificate identity.
 */
class SingleCertificateProvider : CertificateProvider, ConfigurationHelperSetup {
  companion object {
    private val LOGGER = LoggerFactory.getLogger(SingleCertificateProvider::class.java)
  }

  val privateKey: PrivateKey

  val publicKey: PublicKey

  val certificateChain: MutableList<X509Certificate>?

  /**
   * List of supported certificate type in order preference.
   */
  override val supportedCertificateTypes: MutableList<CertificateType>?

  override val supportedCertificateKeyAlgorithms: MutableList<CipherSuite.CertificateKeyAlgorithm>?

  /**
   * Enable key pair verification. Check, if key-pair is supported by JCE
   * and the public key is corresponding to the private key. Enable by default.
   */
  var verifyKeyPair: Boolean = false

  /**
   * Create static certificate provider from private key and certificate chain.
   * The private key and the public key of the node's certificate (at index 0)
   * must be a key pair, otherwise signing and verification will fail.
   *
   * @param privateKey private key of identity.
   * @param certificateChain certificate chain for identity. The public key of the
   * node's certificate (at index 0) must be related with the private key.
   * @param supportedCertificateTypes list of supported certificate types ordered
   * by preference
   * @throws NullPointerException if the private key or certificate chain is `null`
   * @throws IllegalArgumentException if the certificate chain is empty
   */
  constructor(
    privateKey: PrivateKey?,
    certificateChain: Array<Certificate>?,
    supportedCertificateTypes: Array<CertificateType>?,
  ) : this(privateKey, certificateChain, supportedCertificateTypes?.asList())

  /**
   * Create static certificate provider from private key and certificate chain.
   * The private key and the public key of the node's certificate (at index 0)
   * must be a key pair, otherwise signing and verification will fail.
   *
   * @param privateKey private key of identity.
   * @param certificateChain certificate chain for identity. The public key of
   * the node's certificate (at index 0) must be related with the private key.
   * @param supportedCertificateTypes list of supported certificate types ordered
   * by preference
   * @throws NullPointerException if the private key or certificate chain is `null`
   * @throws IllegalArgumentException if the certificate chain is empty or the
   * list of certificate types contains unsupported types.
   */
  constructor(
    privateKey: PrivateKey?,
    certificateChain: Array<Certificate>?,
    supportedCertificateTypes: List<CertificateType>?,
  ) {
    requireNotNull(privateKey) { "Private key must not be null!" }
    requireNotNull(certificateChain) { "Certificate chain must not be null!" }
    require(certificateChain.isNotEmpty()) { "Certificate chain must not be empty!" }
    if (supportedCertificateTypes != null) {
      require(supportedCertificateTypes.isNotEmpty()) { "Certificate types must not be empty!" }
      supportedCertificateTypes.forEach { certificateType ->
        require(certificateType.isSupported) { "Certificate type $certificateType is not supported!" }
      }
    }
    this.privateKey = privateKey
    this.publicKey = certificateChain[0].publicKey

    var supportedCertificateTypes0 = supportedCertificateTypes
    if (supportedCertificateTypes0 == null) {
      // default X.509
      supportedCertificateTypes0 = ArrayList(1)
      supportedCertificateTypes0.add(CertificateType.X_509)
    }
    if (supportedCertificateTypes0.contains(CertificateType.X_509)) {
      this.certificateChain = SslContextUtil.asX509Certificates(certificateChain).asList().toMutableList()
    } else {
      this.certificateChain = null
    }
    this.supportedCertificateTypes = Collections.unmodifiableList(supportedCertificateTypes0)
    this.supportedCertificateKeyAlgorithms =
      mutableListOf(
        CipherSuite.CertificateKeyAlgorithm.getAlgorithm(publicKey)!!,
      )
  }

  /**
   * Create static certificate provider from private and public key.
   *
   * Only supports [CertificateType.RAW_PUBLIC_KEY]. The private key and the
   * public key must be a key pair, otherwise signing and verification will fail.
   *
   * @param privateKey private key of identity
   * @param publicKey public key of identity
   * @throws NullPointerException if the private or public key is `null`.
   */
  constructor(privateKey: PrivateKey?, publicKey: PublicKey?) {
    requireNotNull(privateKey) { "Private key must not be null!" }
    requireNotNull(publicKey) { "Public key must not be null!" }
    this.privateKey = privateKey
    this.publicKey = publicKey
    this.certificateChain = null
    this.supportedCertificateTypes = mutableListOf(CertificateType.RAW_PUBLIC_KEY)
    this.supportedCertificateKeyAlgorithms =
      mutableListOf(
        CipherSuite.CertificateKeyAlgorithm.getAlgorithm(publicKey)!!,
      )
  }

  /**
   * Enable/Disable the verification of the provided pair. A key pair consists
   * of a private and related public key. Signing and verification will fail,
   * if the keys are not related.
   *
   * @param enable `true` to enable verification (default), `false`, to disable it.
   * @return this certificate provider for command chaining.
   */
  fun setVerifykeyPair(enable: Boolean): SingleCertificateProvider {
    this.verifyKeyPair = enable
    return this
  }

  override fun requestCertificateIdentity(
    cid: ConnectionId,
    client: Boolean,
    issuers: MutableList<X500Principal>?,
    serverNames: ServerNames?,
    certificateKeyAlgorithms: MutableList<CipherSuite.CertificateKeyAlgorithm>?,
    signatureAndHashAlgorithms: MutableList<SignatureAndHashAlgorithm>?,
    curves: MutableList<XECDHECryptography.SupportedGroup>?,
  ): CertificateIdentityResult {
    return if (certificateChain != null) {
      CertificateIdentityResult(cid, privateKey, certificateChain)
    } else {
      CertificateIdentityResult(cid, privateKey, publicKey)
    }
  }

  override fun setResultHandler(resultHandler: HandshakeResultHandler) {
    // empty implementation
  }

  override fun setupConfigurationHelper(helper: CertificateConfigurationHelper?) {
    requireNotNull(helper) { "Certificate configuration helper must not be null!" }
    try {
      helper.verifyKeyPair(privateKey, publicKey)
    } catch (ex: IllegalArgumentException) {
      if (verifyKeyPair) {
        throw IllegalStateException(ex.message)
      } else {
        LOGGER.warn("Mismatching key-pair, causing failure when used!", ex)
      }
    }
    if (certificateChain != null) {
      helper.addConfigurationDefaultsFor(this.certificateChain)
    } else {
      helper.addConfigurationDefaultsForTrusts(this.publicKey)
    }
  }
}
