/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.cipher

import io.kaxis.config.CertificateAuthenticationMode
import io.kaxis.dtls.CertificateType
import io.kaxis.dtls.SignatureAndHashAlgorithm
import io.kaxis.dtls.extensions.SupportedPointFormatsExtension
import io.kaxis.util.Utility
import java.security.PublicKey
import java.security.cert.X509Certificate

/**
 * Cipher suites and parameters.
 */
class CipherSuiteParameters {
  /**
   * General mismatch.
   * - [CipherSuiteParameters.GeneralMismatch.CIPHER_SUITE]
   * - [CipherSuiteParameters.GeneralMismatch.EC_FORMAT]
   * - [CipherSuiteParameters.GeneralMismatch.EC_GROUPS]
   */
  var generalMismatch: GeneralMismatch? = null

  /**
   * Certificate based mismatch.
   */
  var certificateMismatch: CertificateBasedMismatch? = null

  val publicKey: PublicKey?
  val certificateChain: MutableList<X509Certificate>?
  val clientAuthenticationMode: CertificateAuthenticationMode

  val cipherSuites: MutableList<CipherSuite>
  val serverCertTypes: MutableList<CertificateType>
  val clientCertTypes: MutableList<CertificateType>
  val supportedGroups: MutableList<XECDHECryptography.SupportedGroup>
  val signatures: MutableList<SignatureAndHashAlgorithm>
  val format: SupportedPointFormatsExtension.ECPointFormat?

  var selectedCipherSuite: CipherSuite? = null
  var selectedServerCertificateType: CertificateType? = null
  var selectedClientCertificateType: CertificateType? = null
  var selectedSignature: SignatureAndHashAlgorithm? = null
  var selectedSupportedGroup: XECDHECryptography.SupportedGroup? = null

  /**
   * Create common cipher suites and parameters.
   * @param publicKey peer's public key. Maybe `null`.
   * @param certificateChain peer's certificate chain. Maybe `null`
   * @param clientAuthenticationMode client authentication mode
   * @param cipherSuites list of common cipher suites
   * @param serverCertTypes list of common server certificate types
   * @param clientCertTypes list of common client certificate types
   * @param supportedGroups list of common supported groups (curves)
   * @param signatures list of common signatures and algorithms.
   * @param format common ec point format. Only [SupportedPointFormatsExtension.ECPointFormat.UNCOMPRESSED] is supported
   */
  constructor(
    publicKey: PublicKey? = null,
    certificateChain: MutableList<X509Certificate>? = null,
    clientAuthenticationMode: CertificateAuthenticationMode,
    cipherSuites: MutableList<CipherSuite>,
    serverCertTypes: MutableList<CertificateType>,
    clientCertTypes: MutableList<CertificateType>,
    supportedGroups: MutableList<XECDHECryptography.SupportedGroup>,
    signatures: MutableList<SignatureAndHashAlgorithm>,
    format: SupportedPointFormatsExtension.ECPointFormat?,
  ) {
    this.publicKey = publicKey
    this.certificateChain = certificateChain
    this.clientAuthenticationMode = clientAuthenticationMode
    this.cipherSuites = cipherSuites
    this.serverCertTypes = serverCertTypes
    this.clientCertTypes = clientCertTypes
    this.supportedGroups = supportedGroups
    this.signatures = signatures
    this.format = format
  }

  /**
   * Create common cipher suites and parameters.
   * @param publicKey peer's public key. Maybe `null`
   * @param certificateChain peer's certificate chain. Maybe `null`
   * @param others other parameters
   */
  constructor(publicKey: PublicKey?, certificateChain: MutableList<X509Certificate>?, others: CipherSuiteParameters) {
    this.publicKey = publicKey
    this.certificateChain = certificateChain
    this.clientAuthenticationMode = others.clientAuthenticationMode
    this.cipherSuites = others.cipherSuites
    this.serverCertTypes = others.serverCertTypes
    this.clientCertTypes = others.clientCertTypes
    this.supportedGroups = others.supportedGroups
    this.signatures = others.signatures
    this.format = others.format
    this.selectedCipherSuite = others.selectedCipherSuite
    this.selectedServerCertificateType = others.selectedServerCertificateType
    this.selectedClientCertificateType = others.selectedClientCertificateType
    this.selectedSupportedGroup = others.selectedSupportedGroup
    this.selectedSignature = others.selectedSignature
  }

  /**
   * Select cipher suite.
   * @param cipherSuite selected cipher suite
   * @throws NullPointerException if the cipher suite is `null`
   * @throws IllegalArgumentException if the cipher suite is not in the list of common cipher suites
   */
  fun select(cipherSuite: CipherSuite?) {
    requireNotNull(cipherSuite) { "Cipher Suite must not be null!" }
    require(cipherSuites.contains(cipherSuite)) { "$cipherSuite is no common cipher suite!" }
    selectedCipherSuite = cipherSuite
  }

  /**
   * Select server certificate type.
   * @param type selected server certificate type. Maybe `null`, if not available.
   * @throws IllegalArgumentException if the certificate type is not in the list of common server certificate types.
   */
  fun selectServerCertificateType(type: CertificateType?) {
    require(type != null && serverCertTypes.contains(type)) {
      "$type server certificate type is no common certificate type."
    }
    selectedServerCertificateType = type
  }

  /**
   * Select client certificate type.
   * @param type selected client certificate type. Maybe `null`, if not available.
   * @throws IllegalArgumentException if the certificate type is not in the list of common client certificate types.
   */
  fun selectClientCertificateType(type: CertificateType?) {
    require(type != null && clientCertTypes.contains(type)) {
      "$type client certificate type is no common certificate type."
    }
    selectedClientCertificateType = type
  }

  /**
   * Select supported group/curve.
   * @param group selected supported group. Maybe `null`, if not available.
   * @throws IllegalArgumentException if the supported group is not in the list of common supported group.
   */
  fun selectSupportedGroup(group: XECDHECryptography.SupportedGroup?) {
    require(group != null && supportedGroups.contains(group)) { "$group is no common group/curve." }
    selectedSupportedGroup = group
  }

  /**
   * Select signature and hash algorithm.
   * @param signature selected signature and hash algorithm. Maybe `null`, if not available.
   * @throws IllegalArgumentException if the signature and hash algorithm is not in the list of common signature and hash algorithms
   */
  fun selectSignatureAndHashAlgorithm(signature: SignatureAndHashAlgorithm?) {
    require(signature != null && signatures.contains(signature)) {
      "$signature is no common signature and hash algorithm."
    }
    selectedSignature = signature
  }

  /**
   * Gets mismatch summary.
   * @return mismatch summary, or `null`, if not available.
   */
  val mismatchSummary: String?
    get() {
      return if (generalMismatch != null) {
        generalMismatch?.message
      } else if (certificateMismatch != null) {
        certificateMismatch?.message
      } else {
        null
      }
    }

  /**
   * Get details description of mismatch.
   * @return mismatch details description, or `null`, if not available.
   */
  val mismatchDescription: String?
    get() {
      var summary = mismatchSummary
      if (summary != null) {
        val builder = StringBuilder(summary)
        builder.append(Utility.LINE_SEPARATOR)
        builder.append("\tcipher suites: ")
        cipherSuites.forEach { cipherSuite ->
          builder.append(cipherSuite.name).append(",")
        }
        builder.setLength(builder.length - 1)
        if (CertificateBasedMismatch.CERTIFICATE_EC_GROUPS == certificateMismatch) {
          builder.append(Utility.LINE_SEPARATOR).append("\t\tec-groups: ")
          supportedGroups.forEach { group ->
            builder.append(group.name).append(",")
          }
          builder.setLength(builder.length - 1)
        } else if (CertificateBasedMismatch.CERTIFICATE_SIGNATURE_ALGORITHMS == certificateMismatch ||
          CertificateBasedMismatch.CERTIFICATE_PATH_SIGNATURE_ALGORITHMS == certificateMismatch
        ) {
          builder.append(Utility.LINE_SEPARATOR).append("\t\tsignatures: ")
          signatures.forEach { sign ->
            builder.append(sign.jcaName).append(",")
          }
          builder.setLength(builder.length - 1)
        }

        summary = builder.toString()
      }
      return summary
    }

  override fun toString(): String {
    val builder = StringBuilder()
    builder.append("cipher suites: ")
    toEnumStringBuilder(builder, cipherSuites, selectedCipherSuite)
    if (!certificateChain.isNullOrEmpty()) {
      builder.append("x509-DN: [").append(certificateChain[0].subjectX500Principal.name)
      builder.append("]").append(Utility.LINE_SEPARATOR)
    }
    if (publicKey != null) {
      if (CertificateAuthenticationMode.NEEDED == clientAuthenticationMode) {
        builder.append("client certificate required")
      } else if (CertificateAuthenticationMode.WANTED == clientAuthenticationMode) {
        builder.append("client certificate wanted")
      } else {
        builder.append("no client certificate")
      }
      builder.append(Utility.LINE_SEPARATOR)
    }
    builder.append("server certificate types: ")
    toEnumStringBuilder(builder, serverCertTypes, selectedServerCertificateType)
    builder.append("client certificate types: ")
    toEnumStringBuilder(builder, clientCertTypes, selectedClientCertificateType)
    builder.append("ec-groups: ")
    toEnumStringBuilder(builder, supportedGroups, selectedSupportedGroup)
    builder.append("signatures: ")
    signatures.forEach { sign ->
      if (selectedSignature == sign) {
        builder.append("#")
      }
      builder.append(sign.jcaName).append(",")
    }
    builder.setLength(builder.length - 1)
    builder.append(Utility.LINE_SEPARATOR)
    return builder.toString()
  }

  private inline fun <reified E : Enum<E>, EL : MutableList<E>> toEnumStringBuilder(
    builder: StringBuilder,
    enums: EL,
    target: E?,
  ) {
    enums.forEach {
      if (it == target) {
        builder.append("#")
      }
      builder.append(it.name).append(",")
    }
    builder.setLength(builder.length - 1)
    builder.append(Utility.LINE_SEPARATOR)
  }

  /**
   * General negotiation mismatch.
   */
  enum class GeneralMismatch(val message: String) {
    /**
     * Peers have no common cipher suite.
     */
    CIPHER_SUITE("Peers have no common cipher suite."),

    /**
     * Peers have no common ec-point format.
     */
    EC_FORMAT("Peers have no common ec-point format."),

    /**
     * Peers have no common ec-groups format.
     */
    EC_GROUPS("Peers have no common ec-groups."),
  }

  /**
   * Certificate based negotiation mismatch.
   */
  enum class CertificateBasedMismatch(val message: String) {
    /**
     * Peers have no common server certificate type.
     */
    SERVER_CERT_TYPE("Peers have no common server certificate type."),

    /**
     * Peers have no common client certificate type.
     */
    CLIENT_CERT_TYPE("Peers have no common client certificate type."),

    /**
     * Peers have no common signature and hash algorithm.
     */
    SIGNATURE_ALGORITHMS("Peers have no common signature and hash algorithm."),

    /**
     * The peer's node certificate uses no common ec-group.
     */
    CERTIFICATE_EC_GROUPS("The peer's node certificate uses no common ec-group."),

    /**
     * The peer's node certificate uses no common signature and hash algorithm.
     */
    CERTIFICATE_SIGNATURE_ALGORITHMS("The peer's node certificate uses no common signature and hash algorithm."),

    /**
     * The peer's certificate-chain uses no common signature and hash algorithm.
     */
    CERTIFICATE_PATH_SIGNATURE_ALGORITHMS("The peer's certificate-chain uses no common signature and hash algorithm."),
  }
}
