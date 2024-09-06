/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls

import io.kaxis.JceProvider
import io.kaxis.dtls.SignatureAndHashAlgorithm.HashAlgorithm.INTRINSIC
import io.kaxis.dtls.SignatureAndHashAlgorithm.SignatureAlgorithm.ED25519
import io.kaxis.dtls.SignatureAndHashAlgorithm.SignatureAlgorithm.ED448
import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.dtls.cipher.CipherSuite.CertificateKeyAlgorithm
import io.kaxis.dtls.cipher.ThreadLocalSignature
import java.security.InvalidKeyException
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.*

/**
 * See [RFC 5246](https://tools.ietf.org/html/rfc5246#appendix-A.4.1), [RFC 8422](https://tools.ietf.org/html/rfc8422#section-5.1.3) and [draft-ietf-tls-md5-sha1-deprecate](https://datatracker.ietf.org/doc/html/draft-ietf-tls-md5-sha1-deprecate-07) for details.
 *
 * **NOTE**: the terms [CipherSuite.CertificateKeyAlgorithm] and `keyAlgorithm` are slightly different and comply to the
 * usage in RFC 5246. The [CipherSuite.CertificateKeyAlgorithm] refers to the cipher suite and indirect to the
 * `ClientCertificateType` of [RFC 5246, 7.4.4. Certificate Request](https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.4). And the `keyAlgorithm` to the actual algorithm
 * of the used public key, e.g. "EC", "RSA", "EdDSA", or "Ed25519"
 */
class SignatureAndHashAlgorithm {
  companion object {
    /** SHA1_with_EcDSA */
    val SHA1_WITH_ECDSA = SignatureAndHashAlgorithm(HashAlgorithm.SHA1, SignatureAlgorithm.ECDSA)

    /** SHA256_with_EcDSA */
    val SHA256_WITH_ECDSA = SignatureAndHashAlgorithm(HashAlgorithm.SHA256, SignatureAlgorithm.ECDSA)

    /** SHA384_with_EcDSA */
    val SHA384_WITH_ECDSA = SignatureAndHashAlgorithm(HashAlgorithm.SHA384, SignatureAlgorithm.ECDSA)

    /** SHA256_with_RSA */
    val SHA256_WITH_RSA = SignatureAndHashAlgorithm(HashAlgorithm.SHA256, SignatureAlgorithm.RSA)

    /** INTRINSIC_with_Ed25519 */
    val INTRINSIC_WITH_ED25519 = SignatureAndHashAlgorithm(INTRINSIC, ED25519)

    /** INTRINSIC_with_Ed448 */
    val INTRINSIC_WITH_ED448 = SignatureAndHashAlgorithm(INTRINSIC, ED448)

    /**
     * Default list of supported signature and hash algorithms. Contains only SHA256_with_EcDSA and SHA256_with_RSA.
     */
    val DEFAULT = Collections.unmodifiableList(arrayListOf(SHA256_WITH_ECDSA, SHA256_WITH_RSA))

    /**
     * Get thread local signature.
     * @param algorithm name of signature algorithm
     * @return thread local signature
     */
    fun getThreadLocalSignature(algorithm: String?): ThreadLocalSignature {
      return ThreadLocalSignature.SIGNATURES[algorithm ?: "UNKNOWN"]
    }

    /**
     * Get signature and hash-algorithm from JCA name.
     * @param jcaName name of signature and hash algorithm. e.g. "SHA256withECDSA". if "with" is not
     * contained in the provided name, [SignatureAndHashAlgorithm.HashAlgorithm.INTRINSIC] is assumed.
     * @return signature and hash-algorithm
     * @throws IllegalArgumentException if unknown
     *
     */
    fun valueOf(jcaName: String): SignatureAndHashAlgorithm {
      var index = jcaName.indexOf("with")
      if (index < 0) {
        index = jcaName.indexOf("WITH")
      }
      var hashAlgorithm: HashAlgorithm? = null
      var signatureAlgorithm: SignatureAlgorithm? = null
      if (0 < index) {
        val hash = jcaName.substring(0, index)
        val signature = jcaName.substring(index + 4, jcaName.length)
        try {
          hashAlgorithm = HashAlgorithm.valueOf(hash)
        } catch (ex: IllegalArgumentException) {
          // NOSONAR
        }
        try {
          signatureAlgorithm = SignatureAlgorithm.valueOf(signature)
        } catch (ex: IllegalArgumentException) {
          // NOSONAR
        }
        if (hashAlgorithm == null && signatureAlgorithm == null) {
          throw IllegalArgumentException("$jcaName is unknown!")
        } else if (hashAlgorithm == null) {
          throw IllegalArgumentException("$jcaName uses a unknown hash-algorithm!")
        } else if (signatureAlgorithm == null) {
          throw IllegalArgumentException("$jcaName uses a unknown signature-algorithm!")
        }
      } else {
        hashAlgorithm = INTRINSIC
        signatureAlgorithm = SignatureAlgorithm.intrinsicValueOf(jcaName)
      }
      return SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm)
    }

    /**
     * Get list of signature and hash algorithms used by the certificate chain.
     * @param certificateChain certificate chain, May be `null`.
     * @return list of signature and hash-algorithms
     * @throws IllegalArgumentException if certificate chain contains a unknown signature-algorithm and hash-algorithm or that is not supported by the JRE.
     */
    fun getSignatureAlgorithms(
      certificateChain: MutableList<X509Certificate>?,
    ): MutableList<SignatureAndHashAlgorithm> {
      return arrayListOf<SignatureAndHashAlgorithm>().apply result@{
        if (!certificateChain.isNullOrEmpty()) {
          certificateChain.forEach { certificate ->
            val sigAlgName = certificate.sigAlgName
            val signature = valueOf(sigAlgName)
            require(signature.isSupported) { "$sigAlgName is not supported by JCE!" }
            if (!this@result.contains(signature)) {
              this@result.add(signature)
            }
          }
        }
      }
    }

    /**
     * Ensure, that the list contains a signature and hash algorithms usable by the public key. Adds a signature and hash
     * algorithms usable by the public key to the list, if missing.
     *
     * @param algorithms list of default algorithms. If not already supported, a signature and hash algorithms usable by the public key is added to this list.
     * @param publicKey public key. May be `null`.
     * @throws NullPointerException if one of the arguments is `null`.
     * @throws IllegalArgumentException if no signature is supported for this public key
     */
    fun ensureSignatureAlgorithm(
      algorithms: MutableList<SignatureAndHashAlgorithm>?,
      publicKey: PublicKey?,
    ) {
      requireNotNull(algorithms) { "The defaults list must not be null!" }
      requireNotNull(publicKey) { "Public key must not be null!" }
      val signAndHash = getSupportedSignatureAlgorithm(DEFAULT, publicKey)
      if (signAndHash != null) {
        if (!algorithms.contains(signAndHash)) {
          algorithms.add(signAndHash)
        }
        return
      }
      var keyAlgorithmSupported = false
      SignatureAlgorithm.entries.forEach { signatureAlgorithm ->
        if (signatureAlgorithm.isSupported(publicKey.algorithm)) {
          keyAlgorithmSupported = true
          if (signatureAlgorithm.isIntrinsic) {
            val sah = SignatureAndHashAlgorithm(INTRINSIC, signatureAlgorithm)
            if (sah.isSupported(publicKey)) {
              if (!algorithms.contains(sah)) {
                algorithms.add(sah)
              }
              return
            }
          } else {
            HashAlgorithm.entries.forEach { hashAlgorithm ->
              if (hashAlgorithm != INTRINSIC && hashAlgorithm.recommended) {
                val sah = SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm)
                if (sah.isSupported(publicKey)) {
                  if (!algorithms.contains(sah)) {
                    algorithms.add(sah)
                  }
                  return
                }
              }
            }
          }
        }
      }
      if (keyAlgorithmSupported) {
        throw IllegalArgumentException("${publicKey.algorithm} public key is not supported")
      } else {
        throw IllegalArgumentException("${publicKey.algorithm} is not supported")
      }
    }

    /**
     * Get the common signature and hash algorithms in the order of the proposed list.
     * @param proposedSignatureAndHashAlgorithm proposed signature and hash algorithms, ordered
     * @param supportedSignatureAlgorithms supported signature and hash algorithms
     * @return list of common signature and hash algorithms in the order of the proposed list. Empty, if no
     * common signature and hash algorithm is found.
     */
    fun getCommonSignatureAlgorithms(
      proposedSignatureAndHashAlgorithm: MutableList<SignatureAndHashAlgorithm>,
      supportedSignatureAlgorithms: MutableList<SignatureAndHashAlgorithm>,
    ): MutableList<SignatureAndHashAlgorithm> {
      return mutableListOf<SignatureAndHashAlgorithm>().apply result@{
        proposedSignatureAndHashAlgorithm.forEach { algo ->
          if (supportedSignatureAlgorithms.contains(algo)) {
            if (!this@result.contains(algo)) {
              this@result.add(algo)
            }
          }
        }
      }
    }

    /**
     * Gets a signature and hash algorithm that is compatible with a given public key.
     * @param supportedSignatureAlgorithms list of supported signature and hash algorithms.
     * @param publicKey public key
     * @return a signature and hash algorithm that can be used with the provided public key, or `null`, if the
     * public key is not compatible with any of the supported signature and hash algorithms.
     * @throws NullPointerException if any parameter is `null`.
     */
    fun getSupportedSignatureAlgorithm(
      supportedSignatureAlgorithms: MutableList<SignatureAndHashAlgorithm>?,
      publicKey: PublicKey?,
    ): SignatureAndHashAlgorithm? {
      requireNotNull(supportedSignatureAlgorithms) { "The supported list must not be null!" }
      requireNotNull(publicKey) { "Public key must not be null!" }
      supportedSignatureAlgorithms.forEach { supportedAlgorithm ->
        if (supportedAlgorithm.isSupported(publicKey)) {
          return supportedAlgorithm
        }
      }
      return null
    }

    /**
     * Get certificate key algorithm compatible signature and hash algorithms.
     * @param signatureAndHashAlgorithms list of signature and hash algorithms
     * @param certificateKeyAlgorithms list of certificate key algorithms
     * @return list of compatible signature and hash algorithms
     */
    fun getCompatibleSignatureAlgorithms(
      signatureAndHashAlgorithms: MutableList<SignatureAndHashAlgorithm>,
      certificateKeyAlgorithms: MutableList<CertificateKeyAlgorithm>,
    ): MutableList<SignatureAndHashAlgorithm> {
      return arrayListOf<SignatureAndHashAlgorithm>().apply result@{
        signatureAndHashAlgorithms.forEach loop@{ algo ->
          certificateKeyAlgorithms.forEach { certificateKeyAlgorithm ->
            if (algo.isSupported(certificateKeyAlgorithm)) {
              this@result.add(algo)
              return@loop
            }
          }
        }
      }
    }

    /**
     * Checks if the certificate key algorithm is supported by one of the provided signature and hash algorithms.
     * @param supportedSignatureAlgorithms list of supported signature and hash algorithms.
     * @param certificateKeyAlgorithm the certificate key algorithm
     * @return `true`, if one of supported signature and hash algorithms supports the certificate key algorithm, `false`, if none
     * of the supported signature and hash algorithms supports the certificate key algorithm.
     */
    fun isSupportedAlgorithm(
      supportedSignatureAlgorithms: MutableList<SignatureAndHashAlgorithm>,
      certificateKeyAlgorithm: CertificateKeyAlgorithm,
    ): Boolean {
      supportedSignatureAlgorithms.forEach { supportedAlgorithm ->
        if (supportedAlgorithm.isSupported(certificateKeyAlgorithm)) {
          return true
        }
      }
      return false
    }

    /**
     * Checks if the key algorithm is supported by one of the provided signature and hash algorithms.
     * @param supportedSignatureAlgorithms list of supported signature and hash algorithms.
     * @param keyAlgorithm the key algorithm. e.g. "EC", "Ed25519", or "EdDSA".
     * @return `true`, if one of supported signature and hash algorithms supports the key algorithm, `false`, if
     * none of the supported signature and hash algorithms supports the key algorithm.
     */
    fun isSupportedAlgorithm(
      supportedSignatureAlgorithms: MutableList<SignatureAndHashAlgorithm>,
      keyAlgorithm: String,
    ): Boolean {
      supportedSignatureAlgorithms.forEach { supportedAlgorithm ->
        if (supportedAlgorithm.isSupported(keyAlgorithm)) {
          return true
        }
      }
      return false
    }

    /**
     * Checks if all of a given certificates in the chain have been signed using one of the provided signature and
     * hash algorithms.
     * @param supportedSignatureAlgorithms list of supported signature and hash algorithms.
     * @param certificateChain the certificate chain to test.
     * @return `true` if all certificates have been signed using a supported algorithm.
     */
    fun isSignedWithSupportedAlgorithms(
      supportedSignatureAlgorithms: MutableList<SignatureAndHashAlgorithm>,
      certificateChain: MutableList<X509Certificate>,
    ): Boolean {
      certificateChain.forEach { certificate ->
        if (!isSignedWithSupportedAlgorithm(supportedSignatureAlgorithms, certificate)) {
          return false
        }
      }
      return true
    }

    /**
     * Checks if the given certificate have been signed using one of the provided signature and hash algorithms.
     * @param supportedSignatureAlgorithms list of supported signatures and hash algorithms
     * @param certificate the certificate to test
     * @return `true`, if the certificate have been signed using one of the supported algorithms.
     */
    fun isSignedWithSupportedAlgorithm(
      supportedSignatureAlgorithms: MutableList<SignatureAndHashAlgorithm>,
      certificate: X509Certificate,
    ): Boolean {
      val sigAlgName = certificate.sigAlgName
      val sigEdDsa = JceProvider.getEdDsaStandardAlgorithmName(sigAlgName, null)
      if (sigEdDsa != null) {
        if (ED25519.isSupported(sigEdDsa)) {
          return supportedSignatureAlgorithms.contains(INTRINSIC_WITH_ED25519)
        } else if (ED448.isSupported(sigEdDsa)) {
          return supportedSignatureAlgorithms.contains(INTRINSIC_WITH_ED448)
        }
      }
      supportedSignatureAlgorithms.forEach { supportedAlgorithm ->
        if (sigAlgName.equals(supportedAlgorithm.jcaName, true)) {
          return true
        }
      }
      return false
    }
  }

  /**
   * [JCA standard name](https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Signature) corresponding to this combination of hash and signature algorithm.
   *
   * The name returned by this method can be used to instantiate a [java.security.Signature] object like this:
   *
   * ```kt
   * val signature = Signature.newInstance(signatureAndHash.jcaName())
   * ```
   *
   * Nullable if name is not available/not known by this implementation.
   */
  val jcaName: String?
  val hash: HashAlgorithm?
  val signature: SignatureAlgorithm?
  val hashAlgorithmCode: Int
  val signatureAlgorithmCode: Int
  val isSupported: Boolean

  /**
   * Check, if signature and hash algorithm is recommended.
   * @return `true`, if recommended, `false`, otherwise.
   */
  val recommended: Boolean
    get() = signature != null && hash != null && hash.recommended

  /**
   * Creates an instance for a hash and signature algorithm.
   * @param hashAlgorithm the hash algorithm.
   * @param signatureAlgorithm the signature algorithm.
   * @throws NullPointerException if one of the provided arguments was `null`.
   */
  constructor(hashAlgorithm: HashAlgorithm?, signatureAlgorithm: SignatureAlgorithm?) {
    requireNotNull(hashAlgorithm) { "Hash Algorithm must not be null!" }
    requireNotNull(signatureAlgorithm) { "Signature Algorithm must not be null!" }
    this.hash = hashAlgorithm
    this.signature = signatureAlgorithm
    this.hashAlgorithmCode = hashAlgorithm.code
    this.signatureAlgorithmCode = signatureAlgorithm.code
    this.jcaName = buildJcaName()
    this.isSupported = jcaName != null && getThreadLocalSignature(jcaName).isSupported
  }

  /**
   * Creates an instance for corresponding algorithm codes.
   * @param hashAlgorithmCode the hash algorithm's code.
   * @param signatureAlgorithmCode the signature algorithm's code.
   */
  constructor(hashAlgorithmCode: Int, signatureAlgorithmCode: Int) {
    this.hashAlgorithmCode = hashAlgorithmCode
    this.signatureAlgorithmCode = signatureAlgorithmCode
    this.signature = SignatureAlgorithm.getAlgorithmByCode(signatureAlgorithmCode)
    this.hash = HashAlgorithm.getAlgorithmByCode(hashAlgorithmCode)
    this.jcaName = buildJcaName()
    this.isSupported = jcaName != null && getThreadLocalSignature(jcaName).isSupported
  }

  fun buildJcaName(): String? {
    if (hash != null && signature != null) {
      val name = StringBuilder()
      if (hash != INTRINSIC) {
        name.append(hash)
        name.append("with")
      }
      name.append(signature)
      return name.toString()
    }
    return null
  }

  /**
   * Check, if signature and hash algorithm is supported to be used with the public key algorithm by the JRE.
   * @param keyAlgorithm key algorithm. e.g. "EC", "ED25519", or "EdDSA".
   * @return `true`, if supported, `false`, otherwise.
   */
  fun isSupported(keyAlgorithm: String): Boolean {
    if (isSupported) {
      return signature?.isSupported(keyAlgorithm) ?: false
    }
    return false
  }

  /**
   * Check, if signature and hash algorithm is supported to be used with the certificate key algorithm by the JRE.
   * @param certificateKeyAlgorithm certificate key algorithm.
   * @return `true`, if supported, `false`, otherwise.
   */
  fun isSupported(certificateKeyAlgorithm: CertificateKeyAlgorithm): Boolean {
    if (isSupported) {
      return signature?.isSupported(certificateKeyAlgorithm) ?: false
    }
    return false
  }

  /**
   * Check, if signature and hash algorithm is supported to be used with the public key by the JRE.
   * @param publicKey public key
   * @return `true`, if supported, `false`, otherwise.
   */
  fun isSupported(publicKey: PublicKey): Boolean {
    if (isSupported && signature?.isSupported(publicKey.algorithm) == true) {
      val signature = getThreadLocalSignature().current()
      if (signature != null) {
        try {
          signature.initVerify(publicKey)
          return true
        } catch (e: InvalidKeyException) {
          // NOSONAR
        }
      }
    }
    return false
  }

  /**
   * Returns literal name, if signature or hash algorithm is unknown.
   */
  override fun toString(): String {
    if (jcaName != null) {
      return jcaName
    } else {
      val result = StringBuilder()
      if (hash != null) {
        result.append(hash)
      } else {
        result.append(String.format("0x%02x", hashAlgorithmCode))
      }
      result.append("with")
      if (signature != null) {
        result.append(signature)
      } else {
        result.append(String.format("0x%02x", signatureAlgorithmCode))
      }
      return result.toString()
    }
  }

  override fun equals(other: Any?): Boolean {
    return if (this === other) {
      true
    } else if (other == null) {
      false
    } else if (other !is SignatureAndHashAlgorithm) {
      false
    } else {
      this.signatureAlgorithmCode == other.signatureAlgorithmCode && this.hashAlgorithmCode == other.hashAlgorithmCode
    }
  }

  override fun hashCode(): Int {
    return this.hashAlgorithmCode * 256 + this.signatureAlgorithmCode
  }

  /**
   * Get thread local signature for this signature and hash algorithm.
   * @return thread local signature.
   */
  fun getThreadLocalSignature(): ThreadLocalSignature = getThreadLocalSignature(jcaName)

  /**
   * Hash algorithms as defined by [RFC 5246](https://tools.ietf.org/html/rfc5246#appendix-A.4.1).
   *
   * Code is at must 255 (1 byte needed for representation).
   *
   * added [INTRINSIC] defined by [RFC 8422](https://tools.ietf.org/html/rfc8422#section-5.1.3).
   *
   * added recommend for upcoming [draft-ietf-tls-md5-sha1-deprecate](https://datatracker.ietf.org/doc/html/draft-ietf-tls-md5-sha1-deprecate-07). SHA224 is not listed in the "TLS SignatureScheme", therefore it is set to "not recommended".
   *
   */
  enum class HashAlgorithm(val code: Int, val recommended: Boolean) {
    NONE(0, false),
    MD5(1, false),
    SHA1(2, false),
    SHA224(3, false),
    SHA256(4, true),
    SHA384(5, true),
    SHA512(6, true),

    /**
     * Do not hash before sign.
     *
     * @since 2.4
     */
    INTRINSIC(8, true),
    ;

    companion object {
      /**
       * Gets an algorithm by tis code.
       * @param code the algorithm code.
       * @return the algorithm or `null` if no algorithm is defined for the given code by [RFC 5246, Appendix A.4.1](https://tools.ietf.org/html/rfc5246#appendix-A.4.1), or [RFC 8422, Section 5.1.3](https://tools.ietf.org/html/rfc8422#section-5.1.3).
       */
      fun getAlgorithmByCode(code: Int): HashAlgorithm? {
        return when (code) {
          0 -> NONE
          1 -> MD5
          2 -> SHA1
          3 -> SHA224
          4 -> SHA256
          5 -> SHA384
          6 -> SHA512
          8 -> INTRINSIC
          else -> null
        }
      }
    }
  }

  /**
   * Signature algorithm as defined by [RFC 5246](https://tools.ietf.org/html/rfc5246#appendix-A.4.1).
   *
   * Code is at most 255 (1 byte needed for representation). added [ED25519] and [ED448] defined by [RFC 8422](https://tools.ietf.org/html/rfc8422#section-5.1.3).
   *
   */
  enum class SignatureAlgorithm {
    ANONYMOUS(0),
    RSA(1, CertificateKeyAlgorithm.RSA),
    DSA(2, CertificateKeyAlgorithm.DSA),
    ECDSA(3, CertificateKeyAlgorithm.EC, JceProvider.EC, false),

    /**
     * ED25519 signature.
     *
     * @since 2.4
     */
    ED25519(7, CertificateKeyAlgorithm.EC, JceProvider.OID_ED25519, true),

    /**
     * ED448 signature
     *
     * @since 2.4
     */
    ED448(8, CertificateKeyAlgorithm.EC, JceProvider.OID_ED448, true),
    ;

    companion object {
      /**
       * Gets an algorithm by its code.
       * @param code the algorithm's code.
       * @return the algorithm or `null` if no algorithm is defined for the given code by [RFC 5246, Appendix A.4.1](https://tools.ietf.org/html/rfc5246#appendix-A.4.1), or [RFC 8422, Section 5.1.3](https://tools.ietf.org/html/rfc8422#section-5.1.3).
       */
      fun getAlgorithmByCode(code: Int): SignatureAlgorithm? {
        return when (code) {
          0 -> ANONYMOUS
          1 -> RSA
          2 -> DSA
          3 -> ECDSA
          7 -> ED25519
          8 -> ED448
          else -> null
        }
      }

      fun intrinsicValueOf(algorithmName: String): SignatureAlgorithm {
        val standardAlgorithmName = JceProvider.getEdDsaStandardAlgorithmName(algorithmName, null)
        if (standardAlgorithmName != null) {
          entries.forEach { algorithm ->
            if (algorithm.isIntrinsic && algorithm.isSupported(standardAlgorithmName)) {
              return algorithm
            }
          }
          throw IllegalArgumentException("$algorithmName is no supported intrinsic algorithm!")
        }
        throw IllegalArgumentException("$algorithmName is unknown intrinsic algorithm!")
      }
    }

    val code: Int
    val certificateKeyAlgorithm: CertificateKeyAlgorithm?
    val keyAlgorithm: String
    val isIntrinsic: Boolean

    constructor(code: Int) : this(code, null)

    constructor(code: Int, certificateKeyAlgorithm: CertificateKeyAlgorithm?) {
      this.code = code
      this.certificateKeyAlgorithm = certificateKeyAlgorithm
      this.keyAlgorithm = name
      this.isIntrinsic = false
    }

    constructor(
      code: Int,
      certificateKeyAlgorithm: CertificateKeyAlgorithm?,
      keyAlgorithm: String,
      intrinsic: Boolean,
    ) {
      this.code = code
      this.certificateKeyAlgorithm = certificateKeyAlgorithm
      this.keyAlgorithm = keyAlgorithm
      this.isIntrinsic = intrinsic
    }

    /**
     * Checks, if the key algorithm is supported by signature algorithm. The key size is not considered, and
     * so supported signatures may fail to actually use the public key.
     * @param keyAlgorithm key algorithm, e.g. "Ec", "Ed25519", or "EdDSA".
     * @return `true`, if supported, `false`, otherwise.
     */
    fun isSupported(keyAlgorithm: String): Boolean {
      if (this.keyAlgorithm.equals(keyAlgorithm, true)) {
        return JceProvider.isSupported(keyAlgorithm)
      }
      if (ED25519 == this || ED448 == this) {
        val key = JceProvider.getEdDsaStandardAlgorithmName(keyAlgorithm)
        if (key != null) {
          if (ED25519 == this) {
            if (JceProvider.OID_ED25519 == key || JceProvider.EDDSA == key) {
              return JceProvider.isSupported(JceProvider.ED25519)
            }
          }
          if (ED448 == this) {
            if (JceProvider.OID_ED448 == key || JceProvider.EDDSA == key) {
              return JceProvider.isSupported(JceProvider.ED448)
            }
          }
        }
      }
      return false
    }

    /**
     * Checks, if the certificate key algorithm is supported by signature algorithm. The sub-type (e.g.
     * ED25519) and key size is not considered, and so supported signatures may fial to actually use the
     * public key.
     * @param certificateKeyAlgorithm certificate key algorithm.
     * @return `true`, if supported, `false`, otherwise.
     */
    fun isSupported(certificateKeyAlgorithm: CertificateKeyAlgorithm): Boolean {
      return this.certificateKeyAlgorithm == certificateKeyAlgorithm
    }
  }
}
