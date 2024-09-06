/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.cipher

import io.kaxis.Bytes
import io.kaxis.JceProvider
import io.kaxis.dtls.cipher.XECDHECryptography.SupportedGroup
import io.kaxis.util.SecretUtil
import io.kaxis.util.Utility
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.lang.reflect.Method
import java.security.GeneralSecurityException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.EllipticCurve
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.security.auth.Destroyable

/**
 * A helper class to execute the XDH and ECDHE key agreement and key generation.
 *
 * A ECDHE key exchange starts with negotiating a curve. The possible curves are listed at
 * [IANA Transport Layer Security (TLS) Parameters - TLS Supported Groups](http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8).
 * The [SupportedGroup] reflects that and offer the curve's [SupportedGroup.name] (description in the IANA table) or
 * [XECDHECryptography.SupportedGroup.id] (value in the IANA table). You may refer directly a member, e.g. [XECDHECryptography.SupportedGroup.X25519], or
 * get it by id [XECDHECryptography.SupportedGroup.fromId] or by the curve-name [XECDHECryptography.SupportedGroup.values].
 *
 * Once you have a curve negotiated, you crate a instance of [XECDHECryptography] providing this curve as parameter. This will also create the ephemeral key-pair is sent to the
 * other peer. Though the curve is transfered by it's [XECDHECryptography.SupportedGroup.id] (named curve), the public key itself is sent just by
 * the [encodedPoint] and not the ASN.1 encoding ([PublicKey.getEncoded]). Each peer converts the received encoded point of the other peer into a [PublicKey]
 * and applies that to [KeyAgreement.doPhase]. Outside of this class only the encoded point and the [XECDHECryptography.SupportedGroup] is
 * used to do the key exchange. Access to the [PrivateKey] nor [PublicKey] is required outside.
 *
 * ```kt
 * val group = SupportedGroup.X25519
 *
 * // peer 1
 * val ecdhe1 = XECDHECryptography(group)
 * val point1 = ecdhe1.encodedPoint
 *
 * // send group + encoded point to other peer
 *
 * // peer 2, use received group
 * val ecdhe2 = XECDHECryptography(group)
 * val point2 = ecdhe2.encodedPoint
 * val secret2 = ecdhe2.generateSecret(point1)
 *
 * // send own encoded point back to first peer
 *
 * // peer 1
 * val secret1 = ecdhe1.generateSecret(point2)
 *
 * // results in same secrets `secret1` and `secret2`
 * ```
 * See also [RFC 7748](https://tools.ietf.org/html/rfc7748)
 */
class XECDHECryptography : Destroyable {
  companion object {
    private val LOGGER: Logger = LoggerFactory.getLogger(XECDHECryptography::class.java)

    /**
     * The algorithm for the elliptic curve key pair generation. See also [KeyPairGenerator Algorithms](http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator).
     */
    private const val EC_KEYPAIR_GENERATOR_ALGORITHM = "EC"
    private val EC_KEYPAIR_GENERATOR = ThreadLocalKeyPairGenerator(EC_KEYPAIR_GENERATOR_ALGORITHM)

    /**
     * X25519 and X448.
     */
    private const val XDH_KEYPAIR_GENERATOR_ALGORITHM = "XDH"
    private val XDH_KEYPAIR_GENERATOR = ThreadLocalKeyPairGenerator(XDH_KEYPAIR_GENERATOR_ALGORITHM)
    private const val EC_KEY_FACTORY_ALGORITHM = "EC"
    private val EC_KEY_FACTORY = ThreadLocalKeyFactory(EC_KEY_FACTORY_ALGORITHM)
    private const val XDH_KEY_FACTORY_ALGORITHM = "XDH"

    /**
     * XDH key factory. May be used for [XECDHECryptography.XDHPublicKeyApi].
     */
    private val XDH_KEY_FACTORY = ThreadLocalKeyFactory(XDH_KEY_FACTORY_ALGORITHM)

    /**
     * Elliptic Curve Diffie-Hellman algorithm name. See also [KeyAgreement Algorithms](http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyAgreement).
     */
    private const val ECDH_KEY_AGREEMENT_ALGORITHM = "ECDH"
    private val ECDH_KEY_AGREEMENT = ThreadLocalKeyAgreement(ECDH_KEY_AGREEMENT_ALGORITHM)

    /**
     * X25519 and X448.
     */
    private const val XDH_KEY_AGREEMENT_ALGORITHM = "XDH"
    private val XDH_KEY_AGREEMENT = ThreadLocalKeyAgreement(XDH_KEY_AGREEMENT_ALGORITHM)

    /**
     * Use java 17 XDH via reflection.
     */
    @Volatile
    private var xDHPublicKeyApi = XDHpublicKeyReflection.init()

    /**
     * Map of [XECDHECryptography.SupportedGroup.id] to [XECDHECryptography.SupportedGroup].
     */
    private val EC_CURVE_MAP_BY_ID = hashMapOf<Int, SupportedGroup>()

    /**
     * Map of [XECDHECryptography] to [XECDHECryptography.SupportedGroup].
     */
    private val EC_CURVE_MAP_BY_CURVE = hashMapOf<EllipticCurve, SupportedGroup>()
  }

  // Members ///////////////////////////////////////////////

  /**
   * Supported group (curve) of this key exchange.
   */
  val supportedGroup: SupportedGroup

  /**
   * The ephemeral private key.
   */
  var privateKey: PrivateKey?

  /**
   * The ephemeral public key.
   */
  val publicKey: PublicKey // Unit-tests only!

  /**
   * The key exchange contains the used curve by its [XECDHECryptography.SupportedGroup.id], therefore the ASN.1 [PublicKey.getEncoded] is not required.
   */
  val encodedPoint: ByteArray

  // Constructors /////////////////////////////////////////

  /**
   * Creates an ephemeral ECDH key pair for a given supported group.
   * @param supportedGroup a curve as defined in the [IANA Supported Groups Registry](http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8)
   *
   * @throws GeneralSecurityException if the key pair cannot be created from the given supported group, e.g. because
   * the JRE's crypto provider doesn't support the group (Actually, supported from JDK 15.)
   */
  @Throws(GeneralSecurityException::class)
  constructor(supportedGroup: SupportedGroup) {
    val keyPair =
      if (supportedGroup.algorithmName == EC_KEYPAIR_GENERATOR_ALGORITHM) {
        val keyPairGenerator = EC_KEYPAIR_GENERATOR.currentWithCause()
        if (keyPairGenerator != null) {
          val params = ECGenParameterSpec(supportedGroup.name)
          keyPairGenerator.initialize(params, RandomManager.currentSecureRandom())
          keyPairGenerator.generateKeyPair()
        } else {
          throw GeneralSecurityException("${supportedGroup.name} not supported by KeyPairGenerator!")
        }
      } else if (supportedGroup.algorithmName == XDH_KEYPAIR_GENERATOR_ALGORITHM) {
        val keyPairGenerator = XDH_KEYPAIR_GENERATOR.currentWithCause()
        if (keyPairGenerator != null) {
          val params = ECGenParameterSpec(supportedGroup.name)
          keyPairGenerator.initialize(params, RandomManager.currentSecureRandom())
          keyPairGenerator.generateKeyPair()
        } else {
          throw GeneralSecurityException("${supportedGroup.name} not supported by KeyPairGenerator!")
        }
      } else {
        throw GeneralSecurityException("${supportedGroup.name} not supported by KeyPairGenerator!")
      }
    this.privateKey = keyPair.private
    this.publicKey = keyPair.public
    this.supportedGroup = supportedGroup
    this.encodedPoint = supportedGroup.encodedPoint(publicKey)!!
    check("OUT: ", publicKey, encodedPoint)
  }

  /**
   * Generate secret of key exchange.
   * @param encodedPoint the other peer's public key as encoded point
   * @return the premaster secret
   * @throws NullPointerException if `encodedPoint` is `null`.
   * @throws GeneralSecurityException if a crypto error occurred.
   */
  @Throws(GeneralSecurityException::class)
  fun generateSecret(encodedPoint: ByteArray?): SecretKey? {
    requireNotNull(encodedPoint)
    check(privateKey != null) { "private key must not be destroyed" }
    val peersPublicKey = supportedGroup.decodedPoint(encodedPoint)
    val keyAgreement: KeyAgreement? =
      if (supportedGroup.algorithmName == EC_KEYPAIR_GENERATOR_ALGORITHM) {
        ECDH_KEY_AGREEMENT.currentWithCause()
      } else if (xDHPublicKeyApi != null && supportedGroup.algorithmName == XDH_KEYPAIR_GENERATOR_ALGORITHM) {
        XDH_KEY_AGREEMENT.currentWithCause()
      } else {
        throw GeneralSecurityException("${supportedGroup.name} not supported by JCE!")
      }
    check("IN: ", peersPublicKey!!, encodedPoint)

    try {
      return if (keyAgreement != null) {
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(peersPublicKey, true)
        val secret = keyAgreement.generateSecret()
        val secretKey = SecretUtil.create(secret, "TlsPremasterSecret")
        Bytes.clear(secret)
        secretKey
      } else {
        null
      }
    } catch (ex: Throwable) {
      LOGGER.warn("Fail: {} {}", supportedGroup.name, ex.message)
      throw ex
    }
  }

  override fun destroy() {
    privateKey = null
  }

  override fun isDestroyed(): Boolean {
    return privateKey == null
  }

  @Throws(GeneralSecurityException::class)
  private fun check(
    tag: String,
    publicKey: PublicKey,
    point: ByteArray,
  ) {
    if (LOGGER.isDebugEnabled) {
      val asn1 = publicKey.encoded
      var s1 = Utility.byteArray2Hex(asn1)
      var s2 = Utility.byteArray2Hex(point)
      if (s1 == null || s2 == null) {
        throw GeneralSecurityException("DHE: failed to parse encoded point!")
      }
      if (s2.length < s1.length) {
        s2 = String.format("%${s1.length}s", s2)
      }
      LOGGER.debug("{}ASN1 encoded '{}'", tag, s1)
      LOGGER.debug("{}DHE  encoded '{}'", tag, s2)
      for (index in point.indices) {
        if (point[point.size - index - 1] != asn1[asn1.size - index - 1]) {
          throw GeneralSecurityException("DHE: failed to encoded point! ${supportedGroup.name}, position: $index")
        }
      }
    }
  }

  /**
   * The _Supported Groups_ as defined in the official [IANA Transport Layer Security (TLS) Parameters](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8).
   *
   * Also see [RFC 4492, Section 5.1.1 Supported Elliptic Curves Extension](https://tools.ietf.org/html/rfc4492#section-5.1.1).
   */
  @Suppress("ktlint:standard:enum-entry-name-case")
  enum class SupportedGroup {
    sect163k1(1, false),
    sect163r1(2, false),
    sect163r2(3, false),
    sect193r1(4, false),
    sect193r2(5, false),
    sect233k1(6, false),
    sect233r1(7, false),
    sect239k1(8, false),
    sect283k1(9, false),
    sect283r1(10, false),
    sect409k1(11, false),
    sect409r1(12, false),
    sect571k1(13, false),
    sect571r1(14, false),
    secp160k1(15, false),
    secp160r1(16, false),
    secp160r2(17, false),
    secp192k1(18, false),
    secp192r1(19, false),
    secp224k1(20, false),
    secp224r1(21, false),
    secp256k1(22, false),
    secp256r1(23, true),
    secp384r1(24, true),
    secp521r1(25, false),
    brainpoolP256r1(26, false),
    brainpoolP384r1(27, false),
    brainpoolP512r1(28, false),
    X25519(29, 32, XDH_KEYPAIR_GENERATOR_ALGORITHM, true),
    X448(30, 56, XDH_KEYPAIR_GENERATOR_ALGORITHM, true),
    ffdhe2048(256, false),
    ffdhe3072(257, false),
    ffdhe4096(258, false),
    ffdhe6144(259, false),
    ffdhe8192(260, false),
    arbitrary_explicit_prime_curves(65281, false),
    arbitrary_explicit_char2_curves(65282, false),
    ;

    companion object {
      /**
       * Gets the group for a given id.
       * @param id the id
       * @return the group or `null` if no group with the given id is (currently) registered.
       */
      fun fromId(id: Int) = EC_CURVE_MAP_BY_ID[id]

      /**
       * Gets the group for a given public key.
       * @param publicKey the public key
       * @return the group or `null`, if no group with the given id is (currently) registered
       */
      fun fromPublicKey(publicKey: PublicKey?): SupportedGroup? {
        if (publicKey != null) {
          if (publicKey is ECPublicKey) {
            val params = publicKey.params
            return EC_CURVE_MAP_BY_CURVE[params.curve]
          } else if (xDHPublicKeyApi != null && xDHPublicKeyApi!!.isSupporting(publicKey)) {
            try {
              val name = xDHPublicKeyApi!!.getCurveName(publicKey)
              return valueOf(name)
            } catch (ex: GeneralSecurityException) {
              // NOSONAR
            }
          } else {
            // EdDsa work around ...
            val algorithm = publicKey.algorithm
            val oid = JceProvider.getEdDsaStandardAlgorithmName(algorithm)
            if (JceProvider.OID_ED25519 == oid || JceProvider.EDDSA.equals(oid, false)) {
              return X25519
            } else if (JceProvider.OID_ED448 == oid) {
              return X448
            } else {
              LOGGER.warn("No supported curve {}/{}", publicKey.algorithm, oid)
            }
          }
        }
        return null
      }

      /**
       * Checks, if provided public key is a EC or XEC key.
       * @param publicKey the public key
       * @return `true`, if it's a EC of XEC key, `false`, otherwise.
       */
      fun isEcpublicKey(publicKey: PublicKey): Boolean {
        return when (publicKey) {
          is ECPublicKey -> true
          else -> xDHPublicKeyApi != null && xDHPublicKeyApi!!.isSupporting(publicKey)
        }
      }

      /**
       * Check, if all ECDSA certificates uses a supported group (curve) from the provided list.
       * @param list list of supported groups
       * @param certificateChain certificate chain
       * @return `true`, if all ECDSA certificates uses supported group (curve) from the provided list, `false`, otherwise.
       */
      fun isSupported(
        list: List<SupportedGroup>,
        certificateChain: List<X509Certificate>,
      ): Boolean {
        certificateChain.forEach { certificate ->
          val publicKey = certificate.publicKey
          if (isEcpublicKey(publicKey)) {
            val group = fromPublicKey(publicKey)
            if (group == null || !group.isUsable || !list.contains(group)) {
              return false
            }
          }
        }
        return true
      }

      /**
       * Gets all `SupportedGroups` that can be used on this platform.
       * @return the supported groups as unmodifiable list.
       */
      fun getUsableGroups(): List<SupportedGroup> {
        return Initialize.USABLE_GROUPS
      }

      /**
       * Gets the preferred `SupportedGroups`.
       * @return the groups in order of preference as unmodifiable list.
       */
      fun getPreferredGroups(): List<SupportedGroup> {
        return Initialize.PREFERRED_GROUPS
      }

      fun getTypeByName(name: String): SupportedGroup? {
        SupportedGroup.entries.forEach { group ->
          if (group.name == name) {
            return group
          }
        }
        if (LOGGER.isTraceEnabled) {
          LOGGER.trace("Cannot resolve supported group code [{}]", name)
        }
        return null
      }

      fun getTypesByNames(names: List<String>): List<SupportedGroup> {
        return arrayListOf<SupportedGroup>().apply groups@{
          names.forEach { name ->
            val knownGroup = getTypeByName(name)
            if (knownGroup != null) {
              this@groups.add(knownGroup)
            } else {
              throw IllegalArgumentException("Supported Group [$name] is not (yet) supported")
            }
          }
        }
      }
    }

    /**
     * Group's official id as registered with IANA.
     */
    val id: Int

    /**
     * Algorithm name.
     */
    val algorithmName: String
    val keySizeInBytes: Int
    val encodedPointSizeInBytes: Int
    val isUsable: Boolean
    val recommended: Boolean
    val asn1header: ByteArray?
    val keyFactory: ThreadLocalKeyFactory

    /**
     * Create supported group.
     * @param code code according IANA
     * @param recommended `true`, for IANA recommended curves, `false`, otherwise.
     */
    constructor(code: Int, recommended: Boolean) {
      this.id = code
      this.algorithmName = EC_KEYPAIR_GENERATOR_ALGORITHM
      this.recommended = recommended
      var curve: EllipticCurve? = null
      var keySize = 0
      var publicKeySize = 0
      var header: ByteArray? = null
      try {
        val keyPairGenerator = EC_KEYPAIR_GENERATOR.currentWithCause()
        if (keyPairGenerator != null) {
          val genParams = ECGenParameterSpec(name)
          keyPairGenerator.initialize(genParams, RandomManager.currentSecureRandom())
          val publicKey = keyPairGenerator.generateKeyPair().public as ECPublicKey
          curve = publicKey.params.curve
          keySize = (curve.field.fieldSize + Byte.SIZE_BITS - 1) / Byte.SIZE_BITS
          publicKeySize = keySize * 2 + 1
          EC_CURVE_MAP_BY_CURVE[curve] = this
          val h = publicKey.encoded
          header = Arrays.copyOf(h, h.size - publicKeySize)
        }
      } catch (e: Throwable) {
        curve = null
      }
      this.keySizeInBytes = keySize
      this.encodedPointSizeInBytes = publicKeySize
      this.asn1header = header
      this.isUsable = curve != null
      this.keyFactory = EC_KEY_FACTORY
      EC_CURVE_MAP_BY_ID[code] = this
    }

    /**
     * Create supported group.
     * @param code code according IANA
     * @param keySizeInBytes public key size in bytes
     * @param algorithmName JRE name of key pair generator algorithm. Currently only "XDH" is implemented!
     * @param recommended `true`, for IANA recommended curves, `false`, otherwise.
     */
    constructor(code: Int, keySizeInBytes: Int, algorithmName: String, recommended: Boolean) {
      this.id = code
      this.algorithmName = algorithmName
      this.keySizeInBytes = keySizeInBytes
      this.encodedPointSizeInBytes = keySizeInBytes
      this.recommended = recommended
      var header: ByteArray? = null
      var usable: Boolean = false
      try {
        val keyPairGenerator = XDH_KEYPAIR_GENERATOR.currentWithCause()
        if (keyPairGenerator != null) {
          val params = ECGenParameterSpec(name)
          keyPairGenerator.initialize(params, RandomManager.currentSecureRandom())
          val publicKey = keyPairGenerator.generateKeyPair().public
          val h = publicKey.encoded
          header = Arrays.copyOf(h, h.size - keySizeInBytes)
          usable = true
        }
      } catch (e: Throwable) {
        // NOSONAR
      }
      this.isUsable = usable
      this.asn1header = header
      this.keyFactory = XDH_KEY_FACTORY
      EC_CURVE_MAP_BY_ID[code] = this
    }

    /**
     * Get public key as encoded point.
     * @param publicKey public key
     * @return encoded point, or `null`, if not supported
     * @throws NullPointerException if publicKey is `null`
     * @throws GeneralSecurityException if an encoding is not supported
     */
    @Throws(GeneralSecurityException::class)
    fun encodedPoint(publicKey: PublicKey?): ByteArray? {
      requireNotNull(publicKey) { "public key must not be null!" }
      val result = publicKey.encoded ?: throw GeneralSecurityException("$name not supported!")
      return Arrays.copyOfRange(result, asn1header?.size ?: 0, result.size)
    }

    /**
     * Get public key from encoded point.
     * @param encodedPoint encoded point
     * @return public key
     * @throws NullPointerException if encoded point is `null`
     * @throws IllegalArgumentException if encoded point has mismatching length.
     * @throws GeneralSecurityException if an error occurred
     */
    @Throws(GeneralSecurityException::class)
    fun decodedPoint(encodedPoint: ByteArray?): PublicKey? {
      requireNotNull(encodedPoint) { "encoded point must not be null!" }
      require(encodedPointSizeInBytes == encodedPoint.size) {
        "encoded point must have $encodedPoint bytes, not ${encodedPoint.size}!"
      }
      if (asn1header != null) {
        val encodedKey = Bytes.concatenate(asn1header, encodedPoint)
        val keySpec = X509EncodedKeySpec(encodedKey)
        val factory = keyFactory.currentWithCause()
        if (factory != null) {
          return factory.generatePublic(keySpec)
        }
      }
      return null
    }
  }

  /**
   * Prepare usable and preferred list of ec groups.
   */
  private object Initialize {
    /**
     * Default preferred supported groups. Keep [XECDHECryptography.SupportedGroup.secp256r1] at
     * the first position for backwards compatibility, when the server doesn't receive the "supported
     * elliptic curves extension".
     */
    private val PREFERRED: Array<SupportedGroup> =
      arrayOf(SupportedGroup.secp256r1, SupportedGroup.X25519, SupportedGroup.X448, SupportedGroup.secp384r1)
    val USABLE_GROUPS: List<SupportedGroup>
    val PREFERRED_GROUPS: List<SupportedGroup>

    init {
      val usableGroups = arrayListOf<SupportedGroup>()
      val preferredGroups = arrayListOf<SupportedGroup>()

      SupportedGroup.entries.forEach { group ->
        if (group.isUsable) {
          usableGroups.add(group)
        }
      }
      PREFERRED.forEach { group ->
        if (group.isUsable) {
          preferredGroups.add(group)
        }
      }
      if (preferredGroups.isEmpty() && usableGroups.isNotEmpty()) {
        preferredGroups.add(usableGroups[0])
      }
      USABLE_GROUPS = Collections.unmodifiableList(usableGroups)
      PREFERRED_GROUPS = Collections.unmodifiableList(preferredGroups)
    }
  }

  /**
   * API for XDH (X25519/X448) public keys.
   */
  interface XDHPublicKeyApi {
    /**
     * Check, if provided public key is a XDH (X25519/X448) public ke supported by this implementation.
     * @param publicKey public key to check.
     * @return `true`, if public key is a XDH (X25519/X448) public key and supported by this implementation.
     */
    fun isSupporting(publicKey: PublicKey): Boolean

    /**
     * Gets curve name of the public key.
     * @param publicKey public key.
     * @return curve name
     * @throws GeneralSecurityException if not supported by this implementation
     * @see [isSupporting]
     */
    @Throws(GeneralSecurityException::class)
    fun getCurveName(publicKey: PublicKey): String
  }

  /**
   * Implementation of [XECDHECryptography.XDHPublicKeyApi] based on reflection running on java 17 XDH.
   */
  @Suppress("ktlint:standard:property-naming")
  internal class XDHpublicKeyReflection : XDHPublicKeyApi {
    private val XECPublicKeyClass: Class<*>
    private val XECPublicKeyGetParams: Method?
    private val NamedParameterSpecGetName: Method?

    constructor(XECPublicKeyClass: Class<*>?) {
      requireNotNull(XECPublicKeyClass) { "XECPublicKeyClass must not be null!" }
      this.XECPublicKeyClass = XECPublicKeyClass
      this.XECPublicKeyGetParams = null
      this.NamedParameterSpecGetName = null
    }

    constructor(XECPublicKeyClass: Class<*>?, XECPublicKeyGetParams: Method?, NamedParameterSpecGetName: Method?) {
      requireNotNull(XECPublicKeyClass) { "XECPublicKeyClas must not be null!" }
      requireNotNull(XECPublicKeyGetParams) { "XECPublicKeyGetParams must not be null!" }
      requireNotNull(NamedParameterSpecGetName) { "NamedParameterSpecGetName must not be null!" }
      this.XECPublicKeyClass = XECPublicKeyClass
      this.XECPublicKeyGetParams = XECPublicKeyGetParams
      this.NamedParameterSpecGetName = NamedParameterSpecGetName
    }

    override fun isSupporting(publicKey: PublicKey): Boolean {
      return XECPublicKeyClass.isInstance(publicKey)
    }

    @Throws(GeneralSecurityException::class)
    override fun getCurveName(publicKey: PublicKey): String {
      if (XECPublicKeyClass.isInstance(publicKey)) {
        if (XECPublicKeyGetParams != null && NamedParameterSpecGetName != null) {
          try {
            val params = XECPublicKeyGetParams.invoke(publicKey)
            return NamedParameterSpecGetName.invoke(params) as String
          } catch (e: Exception) {
            throw GeneralSecurityException("X25519/X48 not supported by JRE!", e)
          }
        }
      }
      throw GeneralSecurityException("${publicKey.algorithm} not supported!")
    }

    companion object {
      fun init(): XDHPublicKeyApi? {
        try {
          var cls = Class.forName("java.security.spec.NamedParameterSpec")
          val getName = cls.getMethod("getName")
          cls = Class.forName("java.security.interfaces.XECPublicKey")
          val getParams = cls.getMethod("getParams")
          return XDHpublicKeyReflection(cls, getParams, getName)
        } catch (t: Throwable) {
          return null
        }
      }
    }
  }
}
