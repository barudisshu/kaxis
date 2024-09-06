/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.x509.verifier

import io.kaxis.auth.RawPublicKeyIdentity
import io.kaxis.dtls.*
import io.kaxis.dtls.message.AlertMessage
import io.kaxis.dtls.message.handshake.CertificateMessage
import io.kaxis.dtls.x509.CertificateConfigurationHelper
import io.kaxis.dtls.x509.ConfigurationHelperSetup
import io.kaxis.dtls.x509.NewAdvancedCertificateVerifier
import io.kaxis.exception.HandshakeException
import io.kaxis.result.CertificateVerificationResult
import io.kaxis.util.CertPathUtil
import io.kaxis.util.SslContextUtil
import io.kaxis.util.Utility
import org.slf4j.LoggerFactory
import java.net.InetSocketAddress
import java.security.GeneralSecurityException
import java.security.cert.CertPathValidatorException
import java.security.cert.Certificate
import java.security.cert.CertificateExpiredException
import java.security.cert.X509Certificate
import java.util.*
import javax.security.auth.x500.X500Principal

/**
 * New advanced certificate verifier based on collections of trusted X.509 certificates and RPKs.
 */
class StaticNewAdvancedCertificateVerifier : NewAdvancedCertificateVerifier, ConfigurationHelperSetup {
  companion object {
    private val LOGGER = LoggerFactory.getLogger(StaticNewAdvancedCertificateVerifier::class.java)

    private val X509_TRUST_ALL = arrayOf<X509Certificate>()
    private val RPK_TRUST_ALL = arrayOf<RawPublicKeyIdentity>()

    fun builder(): Builder {
      return Builder()
    }
  }

  /**
   * Trusted X.509 certificates.
   */
  val trustedCertificates: Array<X509Certificate>?

  /**
   * RPK certificate verifier to delegate verification.
   */
  val trustedRPKs: Set<RawPublicKeyIdentity>?

  /**
   * List of supported certificate type in order of preference.
   */
  override val supportedCertificateTypes: MutableList<CertificateType>

  /**
   * Use empty list of accepted issuers instead of a list based on the [trustedCertificates].
   */
  val useEmptyAcceptedIssuers: Boolean

  /**
   * Create delegating certificate verifier for X.509 and RPK.
   *
   * @param trustedCertificates trusted X.509 certificates. `null` not support X.509, empty, to trust all.
   * @param trustedRPKs trusted RPK identities. `null` not support RPK, empty, to trust all.
   * @param supportedCertificateTypes list of supported certificate type in order of preference.
   * `null` to create a list based on the provided trusts with Raw Public key before X.509.
   *
   * @throws IllegalArgumentException if both, trustedCertificates and trustedRPKs, are `null`, the
   * supportedCertificateTypes is empty, or the trusts for an provided certificate type are `null`.
   */
  constructor(
    trustedCertificates: Array<X509Certificate>?,
    trustedRPKs: Array<RawPublicKeyIdentity>?,
    supportedCertificateTypes: List<CertificateType>?,
  ) : this(trustedCertificates, trustedRPKs, supportedCertificateTypes, false)

  /**
   * Create delegating certificate verifier for X.509 and RPK.
   *
   * @param trustedCertificates trusted X.509 certificates. `null` not support X.509, empty, to trust all.
   * @param trustedRPKs trusted RPK identities. `null` not support RPK, empty, to trust all.
   * @param supportedCertificateTypes list of supported certificate type in order of preference.
   * `null` to create a list based on the provided trusts with Raw Public key before X.509.
   * @param useEmptyAcceptedIssuers `true` to enable to use a empty list of accepted issuers instead of
   * a list based on the provided certificates.
   * @throws IllegalArgumentException if both, trustedCertificates and trustedRPKs, are `null`, the
   * supportedCertificateTypes is empty, or the trusts for an provided certificate type are `null`.
   */
  constructor(
    trustedCertificates: Array<X509Certificate>?,
    trustedRPKs: Array<RawPublicKeyIdentity>?,
    supportedCertificateTypes: List<CertificateType>?,
    useEmptyAcceptedIssuers: Boolean,
  ) {
    require(trustedCertificates != null || trustedRPKs != null) { "no trusts provided!" }

    var tmpSupportedCertificateTypes = supportedCertificateTypes
    when {
      tmpSupportedCertificateTypes == null -> {
        tmpSupportedCertificateTypes = ArrayList(2)
        if (trustedRPKs != null) {
          tmpSupportedCertificateTypes.add(CertificateType.RAW_PUBLIC_KEY)
        }
        if (trustedCertificates != null) {
          tmpSupportedCertificateTypes.add(CertificateType.X_509)
        }
      }
      tmpSupportedCertificateTypes.isEmpty() -> {
        throw IllegalArgumentException("list of supported certificate types must not be empty!")
      }
      else -> {
        require(!(tmpSupportedCertificateTypes.contains(CertificateType.RAW_PUBLIC_KEY) && trustedRPKs == null)) {
          "RPK support requires RPK trusts!"
        }
        require(!(tmpSupportedCertificateTypes.contains(CertificateType.X_509) && trustedCertificates == null)) {
          "x509support requires x509 trusts!"
        }
      }
    }
    this.trustedCertificates = trustedCertificates?.copyOf()
    this.trustedRPKs = trustedRPKs?.toSet()
    this.supportedCertificateTypes = Collections.unmodifiableList(tmpSupportedCertificateTypes)
    this.useEmptyAcceptedIssuers = useEmptyAcceptedIssuers
  }

  override fun verifyCertificate(
    cid: ConnectionId,
    serverNames: ServerNames,
    remotePeer: InetSocketAddress,
    clientUsage: Boolean,
    verifySubject: Boolean,
    truncateCertificatePath: Boolean,
    message: CertificateMessage,
  ): CertificateVerificationResult {
    LOGGER.debug("Verify for SNI: {}, IP: {}", serverNames, Utility.toLog(remotePeer))
    try {
      var certChain = message.certificateChain
      if (certChain == null) {
        if (trustedRPKs == null) {
          val alert = AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.UNSUPPORTED_CERTIFICATE)
          throw HandshakeException(alert, "RPK verification not enabled!")
        }
        val publicKey = message.publicKey
        if (trustedRPKs.isNotEmpty()) {
          val rpk = RawPublicKeyIdentity(publicKey)
          if (!trustedRPKs.contains(rpk)) {
            LOGGER.debug("Certificate validation failed: Raw Public key is not trusted")
            val alert = AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.BAD_CERTIFICATE)
            throw HandshakeException(alert, "Raw Public Key is not trusted!")
          }
        }
        return CertificateVerificationResult(cid, publicKey)
      } else {
        if (trustedCertificates == null) {
          val alert = AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.UNSUPPORTED_CERTIFICATE)
          throw HandshakeException(alert, "X.509 verification not enabled!")
        }

        try {
          var certificateChain = certChain
          if (!message.isEmpty) {
            val certificate = certChain.certificates[0]
            if (certificate is X509Certificate) {
              if (!CertPathUtil.canBeUsedForAuthentication(certificate, clientUsage)) {
                LOGGER.debug("Certificate validation failed: key usage doesn't match")
                val alert = AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.BAD_CERTIFICATE)
                throw HandshakeException(alert, "Key Usage doesn't match!")
              }
              if (verifySubject) {
                verifyCertificatesSubject(serverNames, remotePeer, certificate)
              }
            }
            certificateChain =
              CertPathUtil.validateCertificatePathWithIssuer(
                truncateCertificatePath,
                certChain,
                trustedCertificates,
              )
          }
          return CertificateVerificationResult(cid, certificateChain)
        } catch (e: CertPathValidatorException) {
          when (val cause = e.cause) {
            is CertificateExpiredException -> {
              LOGGER.debug("Certificate expired: {}", cause.message)
              val alert = AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.CERTIFICATE_EXPIRED)
              throw HandshakeException(alert, "Certificate expired")
            }
            null -> LOGGER.debug("Certificate validation failed: {}", e.message)
            else -> LOGGER.debug("Certificate validation failed: {}/{}", e.message, cause.message)
          }
          val alert = AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.BAD_CERTIFICATE)
          throw HandshakeException(alert, "Certificate chain could not be validated", e)
        } catch (e: GeneralSecurityException) {
          if (LOGGER.isTraceEnabled) {
            LOGGER.trace("Certificate validation failed", e)
          } else if (LOGGER.isDebugEnabled) {
            LOGGER.debug("Certificate validation failed due to {}", e.message)
          }
          val alert = AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.DECRYPT_ERROR)
          throw HandshakeException(alert, "Certificate chain could not be validated", e)
        }
      }
    } catch (e: HandshakeException) {
      LOGGER.debug("Certificate validation failed!", e)
      return CertificateVerificationResult(cid, e)
    }
  }

  /**
   * Verify the certificate's subject.
   *
   * Considers both destination variants, server names and inet address and verify that using
   * the certificate's subject CN and subject alternative names.
   *
   * @param serverNames server names
   * @param remotePeer remote peer
   * @param certificate server's certificate
   * @throws HandshakeException if the verification fails.
   * @throws NullPointerException if the certificate or both identities, the servernames and peer, is `null`.
   */
  @Throws(HandshakeException::class)
  fun verifyCertificatesSubject(
    serverNames: ServerNames?,
    remotePeer: InetSocketAddress?,
    certificate: X509Certificate?,
  ) {
    requireNotNull(certificate) { "Certificate must not be null!" }
    if (serverNames == null && remotePeer == null) {
      // nothing to verify
      return
    }

    var literalIp: String? = null
    var hostname: String? = null

    if (remotePeer != null) {
      hostname = Utility.toHostString(remotePeer)
      val destination = remotePeer.address
      if (destination != null) {
        literalIp = destination.hostAddress
      }
    }
    if (serverNames != null) {
      val serverName = serverNames.getServerName(ServerName.NameType.HOST_NAME)
      if (serverName != null) {
        hostname = serverName.nameAsString
      }
    }
    if (hostname != null && hostname == literalIp) {
      hostname = null
    }
    if (hostname != null) {
      if (!CertPathUtil.matchDestination(certificate, hostname)) {
        val cn = CertPathUtil.getSubjectsCn(certificate)
        LOGGER.debug("Certificate {} validation failed: destination doesn't match", cn)
        val alert = AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.BAD_CERTIFICATE)
        throw HandshakeException(alert, "Certificate $cn: Destination '$hostname' doesn't match!")
      }
    } else {
      if (!CertPathUtil.matchLiteralIP(certificate, literalIp)) {
        val cn = CertPathUtil.getSubjectsCn(certificate)
        LOGGER.debug("Certificate {} validation failed: literal IP doesn't match", cn)
        val alert = AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.BAD_CERTIFICATE)
        throw HandshakeException(alert, "Certificate $cn: Literal IP $literalIp doesn't match!")
      }
    }
  }

  override val acceptedIssuers: MutableList<X500Principal> get() {
    return if (!useEmptyAcceptedIssuers && trustedCertificates != null) {
      CertPathUtil.toSubjects(trustedCertificates.asList())
    } else {
      CertPathUtil.toSubjects(null)
    }
  }

  override fun setResultHandler(resultHandler: HandshakeResultHandler) {
    // empty implementation
  }

  override fun setupConfigurationHelper(helper: CertificateConfigurationHelper?) {
    helper?.addConfigurationDefaultsForTrusts(trustedCertificates)
    trustedRPKs?.forEach { identity ->
      helper?.addConfigurationDefaultsForTrusts(identity.key)
    }
  }

  class Builder {
    /**
     * X.509 certificate verifier to delegate verification.
     */
    var trustedCertificates: Array<X509Certificate>? = null

    /**
     * RPK certificate verifier to delegate verification.
     */
    var trustedRPKs: Array<RawPublicKeyIdentity>? = null

    /**
     * List of supported certificate type in order of preference.
     */
    var supportedCertificateTypes: List<CertificateType>? = null

    /**
     * Use empty list of accepted issuers instead of a list based on the [trustedCertificates].
     */
    var useEmptyAcceptedIssuers: Boolean = false

    /**
     * Set trusted X.509 certificates.
     *
     * @param trustedCertificates trusted X.509 certificates. `null`, trust no one. If not trusted
     * certificates are provided (empty array), all valid X.509 certificates will be trusted (same as [trustedCertificates]).
     *
     * @return this builder for chaining
     *
     * @throws IllegalArgumentException if trustedCertificates contains duplicates
     */
    fun <T : Certificate> setTrustedCertificates(trustedCertificates: Array<T>?): Builder {
      if (trustedCertificates == null) {
        this.trustedCertificates = null
      } else if (trustedCertificates.isEmpty()) {
        this.trustedCertificates = X509_TRUST_ALL
      } else {
        val certificates = SslContextUtil.asX509Certificates(trustedCertificates)
        SslContextUtil.ensureUniqueCertificates(certificates)
        this.trustedCertificates = certificates
      }
      return this
    }

    /**
     * Set to trust all valid certificates.
     *
     * @return this builder for chaining.
     */
    fun setTrustAllCertificates(): Builder {
      this.trustedCertificates = X509_TRUST_ALL
      return this
    }

    /**
     * Set trusted RPK(Raw Public Key) identities.
     *
     * @param trustedRPKs trusted RPK identities. `null`, trust no one. If no trusted RPK identities
     * are provided (empty array), all RPK identities will be trusted (same as [setTrustedRPKs]).
     *
     * @return this builder for chaining
     * @throws IllegalArgumentException if trustedRPKs contains duplicates
     */
    fun setTrustedRPKs(trustedRPKs: Array<RawPublicKeyIdentity>?): Builder {
      // Search for duplicates
      val set = hashSetOf<RawPublicKeyIdentity>()
      trustedRPKs?.forEach { identity ->
        require(set.add(identity)) { "Truststore contains raw public key certificates duplicates: ${identity.name}" }
      }
      this.trustedRPKs = trustedRPKs
      return this
    }

    /**
     * Set to trust all RPK (Raw Public Key) identities.
     *
     * @return this builder for chaining
     */
    fun setTrustAllRPKs(): Builder {
      this.trustedRPKs = RPK_TRUST_ALL
      return this
    }

    /**
     * Set list of supported certificate types in order of preference.
     *
     * @param supportedCertificateTypes list of supported certificate types
     *
     * @return this builder for chaining
     */
    fun setSupportedCertificateTypes(supportedCertificateTypes: List<CertificateType>?): Builder {
      this.supportedCertificateTypes = supportedCertificateTypes
      return this
    }

    /**
     * Set to use an empty accepted issuers list.
     *
     * The list of accepted issuers is sent to the client in the [CertificateRequest] in order
     * to help the client to select a trusted client certificate. In some case, that list may
     * get larger. If the client has a priori knowledge, which certificate is trusted,
     * using an empty list may save traffic. One consequence of sending an empty list may be,
     * that the client sends an untrusted certificate, which then may be rejected. With an accepted
     * issuers, the client may chose to send an empty certificate chain instead.
     *
     * @param useEmptyAcceptedIssuers `true`, to use an empty accepted issuers list, `false`, to
     * generate that list based on the trusted X.509 certificates.
     * @return this builder for chaining
     */
    fun setUseEmptyAcceptedIssuers(useEmptyAcceptedIssuers: Boolean): Builder {
      this.useEmptyAcceptedIssuers = useEmptyAcceptedIssuers
      return this
    }

    /**
     * Check, if any trust is available.
     *
     * @return `true`, if trusts are available, `false`, if not.
     */
    fun hasTrusts(): Boolean = trustedCertificates != null || trustedRPKs != null

    /**
     * Build [NewAdvancedCertificateVerifier].
     *
     */
    fun build(): NewAdvancedCertificateVerifier {
      return StaticNewAdvancedCertificateVerifier(
        trustedCertificates,
        trustedRPKs,
        supportedCertificateTypes,
        useEmptyAcceptedIssuers,
      )
    }
  }
}
