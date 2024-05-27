/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.cipher

import io.kaxis.JceProvider
import io.kaxis.dtls.CertificateType
import io.kaxis.dtls.SignatureAndHashAlgorithm

/**
 * Default cipher suite selector. Select cipher suite matching the available security parameters and algorithms.
 */
class DefaultCipherSuiteSelector : CipherSuiteSelector {
  override fun select(parameters: CipherSuiteParameters): Boolean {
    if (parameters.cipherSuites.isEmpty()) {
      parameters.generalMismatch = CipherSuiteParameters.GeneralMismatch.CIPHER_SUITE
      return false
    }
    parameters.cipherSuites.forEach { cipherSuite ->
      if (select(cipherSuite, parameters)) {
        return true
      }
    }
    return false
  }

  /**
   * Check, if provided cipher suite is supported by both peers. Sets [CipherSuiteParameters.generalMismatch], if ec
   * based cipher suites can not be selected.
   * @param cipherSuite cipher suite to check.
   * @param parameters parameters to be used to check
   * @param `true`, if cipher suite is supported by both peers, `false`, otherwise.
   */
  fun select(
    cipherSuite: CipherSuite,
    parameters: CipherSuiteParameters,
  ): Boolean {
    if (cipherSuite.isEccBase) {
      if (parameters.supportedGroups.isEmpty()) {
        // no common-supported group
        parameters.generalMismatch = CipherSuiteParameters.GeneralMismatch.EC_GROUPS
        return false
      } else if (parameters.format == null) {
        // no common supported format
        parameters.generalMismatch = CipherSuiteParameters.GeneralMismatch.EC_FORMAT
        return false
      }
    }
    return if (cipherSuite.requiresServerCertificateMessage) {
      if (parameters.certificateMismatch == null) {
        return selectForCertificate(parameters, cipherSuite)
      } else {
        false
      }
    } else {
      if (cipherSuite.isEccBase) {
        // PSK_ECDHE requires a selected supported group
        parameters.selectSupportedGroup(parameters.supportedGroups[0])
      }
      // PSK requires a selected cipher suite.
      parameters.select(cipherSuite)
      true
    }
  }

  /**
   * Check, if the common parameters match the peer's certificate-chain, Sets [CipherSuiteParameters.certificateMismatch],
   * if certificate based cipher suites can not be selected. Sets [CipherSuiteParameters.select],
   * [CipherSuiteParameters.selectServerCertificateType], [CipherSuiteParameters.selectSignatureAndHashAlgorithm] and
   * [CipherSuiteParameters.selectClientCertificateType], if the certificate based cipher suite is selected.
   * @param parameters common parameters and certificate-chain.
   * @param cipherSuite cipher suite to check.
   * @return `true`, if the cipher suite is selected, `false`, otherwise.
   * @throws IllegalArgumentException if the certificate-chain is missing or the certificate's key algorithm is not supported.
   */
  fun selectForCertificate(
    parameters: CipherSuiteParameters,
    cipherSuite: CipherSuite,
  ): Boolean {
    val keyAlgorithm = cipherSuite.certificateKeyAlgorithm
    require(JceProvider.isSupported(keyAlgorithm.name)) { "${keyAlgorithm.name} based cipher suites are supported!" }
    if (!keyAlgorithm.isCompatible(parameters.publicKey)) {
      return false
    }
    // make sure that we support the client's proposed
    // server certificate types
    if (parameters.serverCertTypes.isEmpty()) {
      parameters.certificateMismatch = CipherSuiteParameters.CertificateBasedMismatch.SERVER_CERT_TYPE
      return false
    }
    val clientAuthentication = parameters.clientAuthenticationMode
    if (clientAuthentication.useCertificateRequest && parameters.clientCertTypes.isEmpty()) {
      parameters.certificateMismatch = CipherSuiteParameters.CertificateBasedMismatch.CLIENT_CERT_TYPE
      return false
    }
    if (parameters.signatures.isEmpty()) {
      parameters.certificateMismatch = CipherSuiteParameters.CertificateBasedMismatch.SIGNATURE_ALGORITHMS
      return false
    }
    if (cipherSuite.certificateKeyAlgorithm == CipherSuite.CertificateKeyAlgorithm.EC) {
      // check for supported-curve in certificate
      val group = XECDHECryptography.SupportedGroup.fromPublicKey(parameters.publicKey)
      if (group == null || !parameters.supportedGroups.contains(group)) {
        parameters.certificateMismatch = CipherSuiteParameters.CertificateBasedMismatch.CERTIFICATE_EC_GROUPS
        return false
      }
    }
    val signatureAndHashAlgorithm =
      SignatureAndHashAlgorithm.getSupportedSignatureAlgorithm(parameters.signatures, parameters.publicKey)
    if (signatureAndHashAlgorithm == null) {
      parameters.certificateMismatch = CipherSuiteParameters.CertificateBasedMismatch.CERTIFICATE_SIGNATURE_ALGORITHMS
      return false
    }
    var certificateType = parameters.serverCertTypes[0]
    if (certificateType == CertificateType.X_509) {
      require(!parameters.certificateChain.isNullOrEmpty()) { "Certificate type x509 requires a certificate chain!" }
      // check, if certificate-chain is supported
      var supported =
        SignatureAndHashAlgorithm.isSignedWithSupportedAlgorithms(parameters.signatures, parameters.certificateChain)
      if (supported) {
        supported =
          XECDHECryptography.SupportedGroup.isSupported(parameters.supportedGroups, parameters.certificateChain)
      }
      if (!supported) {
        // x509 is not supported, because the certificate chain
        // contains unsupported signature hash algorithms or groups (curves).
        if (parameters.serverCertTypes.contains(CertificateType.RAW_PUBLIC_KEY)) {
          certificateType = CertificateType.RAW_PUBLIC_KEY
        } else {
          parameters.certificateMismatch =
            CipherSuiteParameters.CertificateBasedMismatch.CERTIFICATE_PATH_SIGNATURE_ALGORITHMS
          return false
        }
      }
    }
    parameters.select(cipherSuite)
    parameters.selectServerCertificateType(certificateType)
    parameters.selectSignatureAndHashAlgorithm(signatureAndHashAlgorithm)
    parameters.selectSupportedGroup(parameters.supportedGroups[0])
    if (clientAuthentication.useCertificateRequest) {
      parameters.selectClientCertificateType(parameters.clientCertTypes[0])
    } else {
      parameters.selectClientCertificateType(null)
    }
    return true
  }
}
