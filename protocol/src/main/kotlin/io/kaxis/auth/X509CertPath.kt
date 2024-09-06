/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.auth

import io.kaxis.Bytes
import io.kaxis.util.CertPathUtil
import java.io.ByteArrayInputStream
import java.security.cert.*

/**
 * A path of X.509 certificates asserting the identity of a peer.
 *
 * The path is an ordered list of X.509 certificates with the target (containing the asserted identity) at first position
 * and the certificate issued by the trust anchor at the end of the list.
 */
class X509CertPath : AbstractExtensiblePrincipal<X509CertPath> {
  companion object {
    private val TYPE_X509 = "X.509"
    private val ENCODING = "PkiPath"

    /**
     * Creates a new instance from a _PkiPath_ encoded certificate chain.
     * @param encodedPath The encoded chain.
     * @return The certificate chain.
     * @throws IllegalArgumentException if the given byte array does cannot be parsed into an X.509 certificate chain.
     */
    fun fromBytes(encodedPath: ByteArray): X509CertPath {
      try {
        val factory = CertificateFactory.getInstance(TYPE_X509)
        val certPath = factory.generateCertPath(ByteArrayInputStream(encodedPath), ENCODING)
        return X509CertPath(certPath)
      } catch (e: CertificateException) {
        throw IllegalArgumentException("byte array does not contain X.509 certificate path")
      }
    }

    /**
     * Create x509 certificate path from array certificate chain.
     * @param certificateChain chain of certificates
     * @return created x509 certificate path
     * @throws NullPointerException if provided certificate chain is `null`
     * @throws IllegalArgumentException if certificate chain is empty, or a certificate is provided, which is no x509 certificate.
     */
    fun fromCertificateChain(certificateChain: List<Certificate>?): X509CertPath {
      requireNotNull(certificateChain) { "Certificate chain must not be null!" }
      require(certificateChain.isNotEmpty()) { "Certificate chain must not be empty!" }
      val chain = CertPathUtil.toX509CertificatesList(certificateChain)
      val certPath = CertPathUtil.generateCertPath(chain)
      return X509CertPath(certPath)
    }
  }

  val path: CertPath

  val target: X509Certificate

  /**
   * Creates a new instance of a certificate chain
   * @param certPath the certificate chain asserting the per's identity.
   *
   * @throws IllegalArgumentException if the given certificate chain is empty or does not contain X.509 certificates only.
   */
  constructor(certPath: CertPath) : this(certPath, null)

  /**
   * Creates a new instance of a certificate chain
   * @param certPath the certificate chain asserting the per's identity.
   *  @param additionalInformation Additional information for this principal.
   * @throws IllegalArgumentException if the given certificate chain is empty or does not contain X.509 certificates only.
   */
  private constructor(certPath: CertPath, additionalInformation: AdditionalInfo?) : super(additionalInformation) {
    require(TYPE_X509 == certPath.type) { "Cert path must contain X.509 certificates only" }
    require(certPath.certificates.isNotEmpty()) { "Cert path must not be empty" }
    this.path = certPath
    this.target = certPath.certificates[0] as X509Certificate
  }

  override fun amend(additionInfo: AdditionalInfo): X509CertPath {
    return X509CertPath(path, additionInfo)
  }

  /**
   * Gets a binary representation of this certificate chain using the PkiPath encoding.
   * @return The binary encoding.
   */
  fun toByteArray(): ByteArray {
    return try {
      path.getEncoded(ENCODING)
    } catch (e: CertificateEncodingException) {
      // should not happen because all Java 7 implementations are required
      // to support PkiPath encoding of X.509 certificates
      Bytes.EMPTY_BYTES
    }
  }

  /**
   * Gets the subject DN of the asserted identity of this certificate path.
   */
  override fun getName(): String {
    return target.subjectX500Principal.name
  }

  /**
   * Gets the CN of the subject DN.
   * @return CN, or `null`, if not available
   */
  fun getCN(): String? = CertPathUtil.getSubjectsCn(target)

  override fun equals(other: Any?): Boolean {
    return if (this === other) {
      true
    } else if (other == null) {
      false
    } else if (other !is X509CertPath) {
      false
    } else {
      this.target == other.target
    }
  }

  override fun hashCode(): Int {
    return target.hashCode()
  }

  override fun toString(): String {
    return StringBuilder("x509 [").append(name).append("]").toString()
  }
}
