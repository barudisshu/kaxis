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

import io.kaxis.JceProvider
import io.kaxis.util.Base64
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec

/**
 * A principal representing an authenticated peer's _RawPublicKey_.
 */
class RawPublicKeyIdentity : AbstractExtensiblePrincipal<RawPublicKeyIdentity> {
  companion object {
    private const val BASE_64_ENCODING_OPTIONS = Base64.ENCODE or Base64.URL_SAFE or Base64.NO_PADDING
  }

  private lateinit var niUri: String

  val key: PublicKey

  /**
   * Creates a new instance for a given public key.
   * @param key the public key
   * @param additionalInformation Additional information for this principal.
   * @throws NullPointerException if the key is `null`
   */
  constructor(key: PublicKey?, additionalInformation: AdditionalInfo? = null) : super(additionalInformation) {
    requireNotNull(key) { "Public key must not be null" }
    this.key = key
    createNamedInformationUri(this.key.encoded)
  }

  /**
   * Creates a new instance for a given ASN.1 subject public key info structure.
   * @param subjectInfo the ASN.1 encoded X.509 subject public key info.
   * @param keyAlgorithm the algorithm name to verify that the subject public key uses this key algorithm, or to support currently not supported key algorithms for serialization/deserialization. If `null`, the key algorithm provided by the ASN.1 DER encoded subject public key is used.
   * @param additionalInformation Additional information for this principal.
   * @throws NullPointerException if the subject info is `null`
   * @throws GeneralSecurityException if the JVM does not support the given key algorithm.
   */
  @Throws(GeneralSecurityException::class)
  constructor(
    subjectInfo: ByteArray?,
    keyAlgorithm: String? = null,
    additionalInformation: AdditionalInfo? = null,
  ) : super(
    additionalInformation,
  ) {
    requireNotNull(subjectInfo) { "SubjectPublicKeyInfo must not be null" }

    var specKeyAlgorithm: String?
    try {
      specKeyAlgorithm = io.kaxis.util.Asn1DerDecoder.readSubjectPublicKeyAlgorithm(subjectInfo)
    } catch (ex: IllegalArgumentException) {
      throw GeneralSecurityException(ex.message)
    }
    val spec = X509EncodedKeySpec(subjectInfo)
    if (keyAlgorithm != null) {
      if (specKeyAlgorithm == null) {
        specKeyAlgorithm = keyAlgorithm
      } else if (!JceProvider.equalKeyAlgorithmSynonyms(specKeyAlgorithm, keyAlgorithm)) {
        throw GeneralSecurityException(
          "Provided key algorithm %s doesn't match %s!".format(
            keyAlgorithm,
            specKeyAlgorithm,
          ),
        )
      }
    } else if (specKeyAlgorithm == null) {
      throw GeneralSecurityException("Key algorithm could not be determined!")
    }
    val factory = io.kaxis.util.Asn1DerDecoder.getKeyFactory(specKeyAlgorithm)
    try {
      this.key = factory.generatePublic(spec)
    } catch (ex: RuntimeException) {
      throw GeneralSecurityException(ex.message)
    }
    createNamedInformationUri(subjectInfo)
  }

  private fun createNamedInformationUri(subjectPublicKeyInfo: ByteArray) {
    try {
      val md = MessageDigest.getInstance("SHA-256")
      md.update(subjectPublicKeyInfo)
      val digest = md.digest()
      val base64UrlDigest = Base64.encodeBytes(digest, BASE_64_ENCODING_OPTIONS)
      this.niUri = "ni:///sha-256;$base64UrlDigest"
    } catch (e: Throwable) {
      // NO SONAR
    }
  }

  /**
   * Creates a shallow copy of this principal which contains additional information
   *
   * The additional information can be retrieved from teh returned copy using the [extendedInfo]
   */
  override fun amend(additionInfo: AdditionalInfo): RawPublicKeyIdentity {
    return RawPublicKeyIdentity(key, additionInfo)
  }

  /**
   * Gets the _Named Information_ URI representing this raw public key. The URI is created using the SHA-256 hash algorithm
   * on the key's _SubjectPublicKeyInfo_ as described in [RFC 6920, section 2](https://tools.ietf.org/html/rfc6920#section-2).
   */
  override fun getName(): String = niUri

  /**
   * Gets the key's ASN.1 encoded _SubjectPublicKeyInfo_.
   * @return the subject info
   */
  val subjectInfo: ByteArray
    get() = key.encoded

  override fun toString(): String {
    return "RawPublicKey Identity [$niUri]"
  }

  override fun hashCode(): Int {
    return subjectInfo.contentHashCode()
  }

  /**
   * Checks, if this instance is equal to another object.
   * @return `true`, if the other object is a _RawPublicKeyIdentity_ and has the same _SubjectPublicKeyInfo_ as this instance.
   */
  override fun equals(other: Any?): Boolean {
    if (this === other) {
      return true
    } else if (other == null) {
      return false
    } else if (other !is RawPublicKeyIdentity) {
      return false
    }
    return subjectInfo.contentEquals(other.subjectInfo)
  }
}
