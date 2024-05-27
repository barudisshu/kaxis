/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.provider.protocols

import io.kaxis.*
import org.bouncycastle.crypto.CryptoServicesRegistrar
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.params.DSAKeyParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.tls.*
import org.bouncycastle.tls.crypto.TlsCertificate
import org.bouncycastle.tls.crypto.TlsCryptoParameters
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedDecryptor
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.io.IOException
import java.util.*

/**
 * Bouncycastle DTLS Server.
 * @author galudisu
 */
abstract class AbstractDtlsServer : DefaultTlsServer(BcTlsCrypto(CryptoServicesRegistrar.getSecureRandom())) {
  protected val logger: Logger = LoggerFactory.getLogger(this.javaClass)

  /**
   * Enable by default.
   * @return bool.
   */
  open fun isMutualAuthentication() = true

  @Throws(IOException::class)
  abstract fun getServerCaCert(): Certificate

  @Throws(IOException::class)
  protected abstract fun getServerPrivateKey(): AsymmetricKeyParameter

  @Throws(IOException::class)
  abstract fun getServerCert(): Certificate

  /**
   * **KEY** point.
   * A CID is an identifier carried in the record layer header that gives the recipient additional
   * information for selecting the appropriate security association. In "classical" DTLS, selecting
   * a security association of an incoming DTLS record is accomplished with the help of the 5-tuple.
   *
   * __If the source IP address and/or source port changes during the lifetime of an ongoing DTLS session,
   * then the receiver will be unable to locate the correct security context.__
   *
   * ```
   * struct {
   *     opaque cid<0..2^8-1>;
   * } ConnectionId;
   * ```
   *
   * A server willing to use CIDs will respond with a "connection_id" extension in the [ServerHello],
   * containing the CID it wishes the client to use when sending messages towards it. A zero-length value
   * indicates that the server will send using the client's CID but does not wish the client to include
   * a CID when sending.
   */
  override fun getNewConnectionID(): ByteArray {
    val cid = ByteArray(6)
    crypto.secureRandom.nextBytes(cid)
    return cid
  }

  public override fun getSupportedVersions(): Array<ProtocolVersion> =
    ProtocolVersion.DTLSv12.downTo(ProtocolVersion.DTLSv10)

  override fun getHeartbeatPolicy(): Short = HeartbeatMode.peer_allowed_to_send

  override fun getHeartbeat(): TlsHeartbeat = DefaultTlsHeartbeat(10_000, 10_000)

  // server side renegotiation shall DENy for DDoS attack.
  override fun getRenegotiationPolicy(): Int = RenegotiationPolicy.DENY

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

  override fun notifyHandshakeBeginning() {
    logger.debug("notify [server] handshake beginning")
    super.notifyHandshakeBeginning()
  }

  override fun notifyHandshakeComplete() {
    logger.debug("notify [server] handshake complete")
    super.notifyHandshakeComplete()
  }

  @Throws(IOException::class)
  override fun notifyClientCertificate(clientCertificate: Certificate?) {
    if (!isMutualAuthentication()) {
      return
    }
    if (clientCertificate == null || clientCertificate.isEmpty) {
      throw TlsFatalAlert(AlertDescription.bad_certificate)
    }

    // verify chain
    try {
      verifyCertificateChain(clientCertificate)
    } catch (e: Throwable) {
      logger.error("Client certificate chain verify fail", e)
      throw TlsFatalAlert(AlertDescription.bad_certificate)
    }

    // verify expired
    try {
      verifyIssuedExpired(clientCertificate)
    } catch (e: Throwable) {
      logger.error("Client certificate expired", e)
      throw TlsFatalAlert(AlertDescription.certificate_expired)
    }

    val trustedCaChain = getServerCaCert()
    // check client CA chains with local CA chain
    val isSameCaChain = verifyExchangeCertificate(clientCertificate, trustedCaChain)
    if (!isSameCaChain) {
      throw TlsFatalAlert(AlertDescription.bad_certificate)
    }
    TlsUtils.checkPeerSigAlgs(context, clientCertificate.certificateList)
  }

  @Throws(IOException::class)
  override fun getCertificateRequest(): CertificateRequest {
    var serverSigAlgs: Vector<*>? = null

    if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(context.serverVersion)) {
      serverSigAlgs = TlsUtils.getDefaultSupportedSignatureAlgorithms(context)
    }
    val rootCert = getServerCaCert()
    val ans1X509s = rootCert.asAsn1s()
    // Distinguished Name (DN) acceptable also see RFC 4346, and update RFC 5246.
    val authorities = Vector<Any>()
    ans1X509s.forEach { ans1X509 ->
      // Only verify CA Subject.
      authorities.add(ans1X509.subject)
    }
    // Or an empty list if all DN want to be considered valid.
    // Currently, server side DN is not needed, and CA subject is required.
    return CertificateRequest(
      shortArrayOf(
        ClientCertificateType.rsa_sign,
        ClientCertificateType.dss_sign,
        ClientCertificateType.ecdsa_sign,
      ),
      serverSigAlgs,
      authorities,
    )
  }

  override fun getSupportedCipherSuites(): IntArray {
    val cipherSuite = super.getSupportedCipherSuites()
    val asymmetricKeyParameter: AsymmetricKeyParameter?
    try {
      asymmetricKeyParameter = getServerPrivateKey()
    } catch (e: IOException) {
      logger.error("Unable to read from asymmetric key, fall back to RSA cipher suites")
      return cipherSuite
    }
    if (!asymmetricKeyParameter.isPrivate) {
      return cipherSuite
    }
    return when (asymmetricKeyParameter) {
      is ECPrivateKeyParameters ->
        intArrayOf(
          CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
          CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
          CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        )

      is RSAKeyParameters ->
        intArrayOf(
          CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
          CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
          CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
          CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
          CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
          CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
          CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
          CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
          CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
          CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
          CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
          CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
          CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
          CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
          CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
          CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
          CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
          CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
          CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
          CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        )

      is DSAKeyParameters ->
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

      else -> {
        logger.error("Unsupported signature algorithm parameter {}", asymmetricKeyParameter.javaClass)
        cipherSuite
      }
    }
  }

  override fun getCredentials(): TlsCredentials? {
    // loading private key asymmetric parameter
    val asymmetricKeyParameter = getServerPrivateKey()

    if (!asymmetricKeyParameter.isPrivate) {
      throw TlsFatalAlert(AlertDescription.decryption_failed)
    }

    val rootCert = getServerCaCert()
    val serverCert = getServerCert()

    val caChains = rootCert.certificateList
    val certChains = serverCert.certificateList

    if (caChains.isEmpty() || certChains.isEmpty()) {
      logger.warn("unable to load certificate")
      throw TlsFatalAlert(AlertDescription.no_certificate)
    }

    // check expired
    try {
      verifyIssuedExpired(serverCert)
    } catch (e: Throwable) {
      logger.warn("the dtls certificates contains expired cert entry")
      throw TlsFatalAlert(AlertDescription.certificate_expired)
    }

    // check issued organization
    val isSameIssued = verifyIssuedCertAssignFrom(serverCert, rootCert)
    if (!isSameIssued) {
      logger.warn("the dtls certificates are not the same with root CA chain issuer")
      throw TlsFatalAlert(AlertDescription.bad_certificate)
    }

    TlsUtils.checkPeerSigAlgs(context, certChains)

    // NOTE: the ca-chain list should be in the order of last "Entry" due to X509 specification
    val cert = Certificate(certChains + caChains)

    try {
      verifyCertificateChain(cert)
    } catch (e: Throwable) {
      logger.error("Server certificate chain verify exception", e)
      throw TlsFatalAlert(AlertDescription.bad_certificate)
    }

    val keyExchangeAlgorithm = context.securityParametersHandshake.keyExchangeAlgorithm
    // extract signature
    val signatureAndHashAlgorithm =
      extractSignatureFromTlsServerContext(cert.getCertificateAt(0), cert.getCertificateAt(1))

    return when (keyExchangeAlgorithm) {
      KeyExchangeAlgorithm.DHE_DSS -> dsaSignerCredentials
      KeyExchangeAlgorithm.DH_anon, KeyExchangeAlgorithm.ECDH_anon -> null
      KeyExchangeAlgorithm.ECDHE_ECDSA, KeyExchangeAlgorithm.DHE_RSA, KeyExchangeAlgorithm.ECDHE_RSA ->
        BcDefaultTlsCredentialedSigner(
          TlsCryptoParameters(context),
          crypto as BcTlsCrypto,
          asymmetricKeyParameter,
          cert,
          signatureAndHashAlgorithm,
        )

      KeyExchangeAlgorithm.RSA -> BcDefaultTlsCredentialedDecryptor(crypto as BcTlsCrypto, cert, asymmetricKeyParameter)

      else -> {
        // NOTE: internal error here; selected a key exchange we don't implement!
        logger.warn("internal error here; selected a key exchange algorithm is not supported: {}", keyExchangeAlgorithm)
        throw TlsFatalAlert(AlertDescription.internal_error)
      }
    }
  }

  /**
   * Make it protected that we can override to a mock one.
   * @return [SignatureAndHashAlgorithm] nullable.
   */
  @Throws(IOException::class)
  private fun extractSignatureFromTlsServerContext(
    certificate: TlsCertificate,
    ca: TlsCertificate,
  ): SignatureAndHashAlgorithm? {
    var sigAlgs = context.securityParametersHandshake.clientSigAlgs
    if (sigAlgs == null) {
      sigAlgs = TlsUtils.getDefaultSignatureAlgorithms(SignatureAlgorithm.rsa)
    }
    var isHandshakeSigAlgMatcher = false
    sigAlgs.forEach { sigAlg ->
      when (sigAlg) {
        is SignatureAndHashAlgorithm -> {
          if (certificate.supportsSignatureAlgorithm(sigAlg.signature) &&
            ca.supportsSignatureAlgorithmCA(sigAlg.signature)
          ) {
            isHandshakeSigAlgMatcher = true
            return@forEach
          }
        }

        else -> {
          // ignored
        }
      }
    }
    if (!isHandshakeSigAlgMatcher) {
      throw TlsFatalAlert(AlertDescription.certificate_unobtainable)
    }
    return getCertSigAndHashAlg(certificate, ca)
  }
}
