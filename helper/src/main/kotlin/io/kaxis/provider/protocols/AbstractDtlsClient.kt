/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.provider.protocols

import io.kaxis.getCertSigAndHashAlg
import io.kaxis.verifyCertificateChain
import io.kaxis.verifyExchangeCertificate
import io.kaxis.verifyIssuedExpired
import org.bouncycastle.crypto.CryptoServicesRegistrar
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.params.DSAKeyParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.tls.*
import org.bouncycastle.tls.crypto.TlsCryptoParameters
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import org.bouncycastle.util.Arrays
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.io.IOException
import java.security.cert.CertificateException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.util.*

/**
 * Bouncycastle DTLS client.
 * @author galudisu
 */
abstract class AbstractDtlsClient : DefaultTlsClient(BcTlsCrypto(CryptoServicesRegistrar.getSecureRandom())) {
  protected val logger: Logger = LoggerFactory.getLogger(this.javaClass)

  /**
   * Enable by default.
   * @return bool
   */
  open fun isMutualAuthentication(): Boolean = true

  /**
   *
   * This structure contains the CID value the client wishes the server to use whe
   * sending messages to the client. A zero-length CID value indicates that the client
   * is prepared to send using a CID but does not wish the server to use one when sending.
   *
   * ```
   * enum {
   *    connection_id(54), (65535)
   * } ExtensionType;
   * ```
   *
   * **WARNING**: No more than 6 bytes of 8 bits <= 6x8=48.
   */
  override fun getNewConnectionID(): ByteArray {
    val cid = ByteArray(6)
    crypto.secureRandom.nextBytes(cid)
    return cid
  }

  @Throws(IOException::class)
  protected abstract fun getClientCaCert(): Certificate

  @Throws(IOException::class)
  protected abstract fun getClientPrivateKey(): AsymmetricKeyParameter

  @Throws(IOException::class)
  protected abstract fun getClientCert(): Certificate

  public override fun getSupportedVersions(): Array<ProtocolVersion> {
    return ProtocolVersion.DTLSv12.downTo(ProtocolVersion.DTLSv10)
  }

  override fun getHeartbeatPolicy(): Short {
    return HeartbeatMode.peer_allowed_to_send
  }

  override fun getHeartbeat(): TlsHeartbeat {
    return DefaultTlsHeartbeat(10_000, 10_000)
  }

  override fun getRenegotiationPolicy(): Int {
    return RenegotiationPolicy.DENY
  }

  override fun notifyAlertRaised(
    alertLevel: Short,
    alertDescription: Short,
    message: String?,
    cause: Throwable?,
  ) {
    logger.debug(
      "alert raised, level: {}, description: {}, message: {}",
      AlertLevel.getName(alertLevel),
      AlertDescription.getName(alertDescription),
      message,
      cause,
    )
    super.notifyAlertRaised(alertLevel, alertDescription, message, cause)
  }

  override fun notifyAlertReceived(
    alertLevel: Short,
    alertDescription: Short,
  ) {
    logger.debug(
      "alert received, level: {}, description: {}",
      AlertLevel.getName(alertLevel),
      AlertDescription.getName(alertDescription),
    )
    super.notifyAlertReceived(alertLevel, alertDescription)
  }

  @Throws(IOException::class)
  override fun notifyHandshakeBeginning() {
    logger.debug("notify [client] handshake beginning")
    super.notifyHandshakeBeginning()
  }

  @Throws(IOException::class)
  override fun notifyHandshakeComplete() {
    logger.debug("notify [client] handshake complete")
    super.notifyHandshakeComplete()
  }

  override fun getSupportedCipherSuites(): IntArray {
    val cipherSuite = super.getSupportedCipherSuites()
    val asymmetricKeyParameter: AsymmetricKeyParameter
    try {
      asymmetricKeyParameter = getClientPrivateKey()
    } catch (e: IOException) {
      logger.error("Unable to read from asymmetric key, fall back to RSA cipher suites")
      return super.getSupportedCipherSuites()
    }
    return when (asymmetricKeyParameter) {
      is ECPrivateKeyParameters -> {
        intArrayOf(
          CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
          CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
          CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
          CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        )
      }

      is RSAKeyParameters -> {
        intArrayOf(
          CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
          CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
          CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
          CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
          CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
          CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
          CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
          CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
          CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
          CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
          CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        )
      }

      is DSAKeyParameters -> {
        intArrayOf(
          CipherSuite.TLS_DHE_DSS_WITH_DES_CBC_SHA,
          CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
          CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
          CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
          CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
          CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
          CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
          CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
        )
      }

      else -> {
        logger.error(
          "Unsupported signature algorithm parameter {}",
          asymmetricKeyParameter.javaClass,
        )
        cipherSuite
      }
    }
  }

  @Throws(IOException::class)
  override fun getClientExtensions(): Hashtable<*, *> {
    val clientExtensions =
      TlsExtensionsUtils.ensureExtensionsInitialised(super.getClientExtensions())
    TlsExtensionsUtils.addConnectionIDExtension(clientExtensions, newConnectionID)
    TlsExtensionsUtils.addEncryptThenMACExtension(clientExtensions)
    // Enable once code-point assigned (only for compatible server though)
    TlsExtensionsUtils.addExtendedMasterSecretExtension(clientExtensions)
    TlsExtensionsUtils.addMaxFragmentLengthExtension(clientExtensions, MaxFragmentLength.pow2_9)
    TlsExtensionsUtils.addTruncatedHMacExtension(clientExtensions)
    return clientExtensions
  }

  override fun getAuthentication(): TlsAuthentication {
    return CachingTlsAuthentication()
  }

  inner class CachingTlsAuthentication : TlsAuthentication {
    /**
     * Notify Server Certificate for Mutual Authentication.
     *
     * @param tlsServerCertificate the server certificate received
     * @throws IOException encoded stream
     */
    @Throws(IOException::class)
    override fun notifyServerCertificate(tlsServerCertificate: TlsServerCertificate) {
      if (!isMutualAuthentication()) {
        return
      }

      if (tlsServerCertificate.certificate == null || tlsServerCertificate.certificate.isEmpty) {
        logger.error("Server certificate disable")
        throw TlsFatalAlert(AlertDescription.bad_certificate)
      }

      // verify chain
      try {
        verifyCertificateChain(tlsServerCertificate.certificate)
      } catch (e: Throwable) {
        logger.error("Client certificate chain verify fail", e)
        throw TlsFatalAlert(AlertDescription.bad_certificate)
      }

      // verify expired
      try {
        verifyIssuedExpired(tlsServerCertificate.certificate)
      } catch (e: CertificateException) {
        logger.error("Server certificate expired", e)
        throw TlsFatalAlert(AlertDescription.bad_certificate)
      }

      val trustedCaChain: Certificate = getClientCaCert()
      // check Server Ca chains with local Ca chain
      val isSameCaChain: Boolean = verifyExchangeCertificate(tlsServerCertificate.certificate, trustedCaChain)
      if (!isSameCaChain) {
        throw TlsFatalAlert(AlertDescription.bad_certificate)
      }
      TlsUtils.checkPeerSigAlgs(context, tlsServerCertificate.certificate.certificateList)
    }

    @Throws(IOException::class)
    override fun getClientCredentials(certificateRequest: CertificateRequest): TlsCredentials? { // NOSONAR
      val certificateTypes = certificateRequest.certificateTypes
      if (certificateTypes == null || !Arrays.contains(certificateTypes, ClientCertificateType.rsa_sign) ||
        !Arrays.contains(certificateTypes, ClientCertificateType.ecdsa_sign) ||
        !Arrays.contains(certificateTypes, ClientCertificateType.dss_sign)
      ) {
        return null
      }
      val rootCert: Certificate = getClientCaCert()
      val clientCert: Certificate = getClientCert()

      try {
        verifyIssuedExpired(clientCert)
      } catch (e: CertificateExpiredException) {
        logger.error("the dtls certificates contains expired cert entry")
        throw TlsFatalAlert(AlertDescription.bad_certificate)
      } catch (e: CertificateNotYetValidException) {
        logger.error("the dtls certificates contains expired cert entry")
        throw TlsFatalAlert(AlertDescription.bad_certificate)
      }

      // 1. check peer
      TlsUtils.checkPeerSigAlgs(context, clientCert.certificateList)

      val certs =
        Certificate(
          clientCert.certificateList + rootCert.certificateList,
        )
      try {
        verifyCertificateChain(certs)
      } catch (e: Throwable) {
        logger.error("Client Certificate chain verify fail", e)
        throw TlsFatalAlert(AlertDescription.bad_certificate)
      }
      val asymmetricKeyParameter: AsymmetricKeyParameter = getClientPrivateKey()

      if (!asymmetricKeyParameter.isPrivate) {
        throw TlsFatalAlert(AlertDescription.unknown_psk_identity)
      }

      // 2. signature and hash algorithm
      val signatureAndHashAlgorithm = getCertSigAndHashAlg(certs.getCertificateAt(0), certs.getCertificateAt(1))

      // 3. signer
      return BcDefaultTlsCredentialedSigner(
        TlsCryptoParameters(context),
        crypto as BcTlsCrypto?,
        asymmetricKeyParameter,
        certs,
        signatureAndHashAlgorithm,
      )
    }
  }
}
