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

import io.kaxis.util.Asn1DerDecoder
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.PublicAPITypo
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.util.*
import javax.crypto.Cipher
import javax.crypto.Mac

/**
 * A cipher suite defines a key exchange algorithm, a bulk cipher algorithm, a MAC algorithm, a pseudo random
 * number (PRF) algorithm and a cipher type.
 *
 * **NOTE**: `ordinal()` must not be used! The order of the cipher-suites reflects the intended default precedence.
 * Extensions may therefore change the related `ordinal()` value.
 *
 * See [RFC 5246](https://tools.ietf.org/html/rfc5246#appendix-A.6) for details. See [Transport Layer Security Parameters](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml) for the official ocdes for the cipher suites.
 *
 * ## CipherSuite
 * Cipher suites order is based on those statements:
 *
 * + ECDHE is preferred as it provides perfect forward secrecy.
 * + AES_128 preferred over AES_192/256 because it's secure enough & faster.
 *     - Source: [Is AES256 more secure than AES128? What's the different?](https://www.quora.com/Is-AES256-more-secure-than-AES128-Whats-the-different)
 *     - Source: [Why most people use 256 bit encryption instead of 128 bit?](https://security.stackexchange.com/questions/14068/why-most-people-use-256-bit-encryption-instead-of-128-bit#19762)
 * + GCM >= CCM_8 ~= CCM >> CBC
 *     - source: [Cipher](https://en.wikipedia.org/wiki/Transport_Layer_Security#Cipher)
 *     - source: [Why does TLS 1.3 support two CCM variants?](https://crypto.stackexchange.com/questions/63796/why-does-tls-1-3-support-two-ccm-variants/64809#64809)
 * + SHA sounds secure enough and so smaller SHA is preferred.
 *     - source: [Why were CBC_SHA256 ciphersuites like TLS_RSA_WITH_AES_128_CBC_SHA256 defined?](https://security.stackexchange.com/questions/84304/why-were-cbc-sha256-ciphersuites-like-tls-rsa-with-aes-128-cbc-sha256-defined)
 *     - source: [SHA1 - SSL/TLS Cipher Suite](https://crypto.stackexchange.com/questions/20572/sha1-ssl-tls-cipher-suite)
 *
 * See more:
 *
 *    https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices
 *
 * /!\ CBC should be avoid /!\ because :
 * - Implementing authenticated decryption (checking padding and mac) without any side channel is hard (see Lucky 13 attack and its variants).
 * - In fact, the current CBC implementation is not "processing time stable" according such "padding" attacks.
 * - One solution is to use the encrypt then mac extension defined in RFC 7366, which is recommended. (from LWM2M 1.0.2 specification)
 *   But currently also does not support RFC 7366.
 *
 * Therefore the CBC cipher suites are not recommended. If you want to use them, you MUST first disable
 * the "recommendedCipherSuitesOnly" in Connection Configuration.
 *
 * PSK cipher suites, ordered by default preference, see getPskCipherSuites
 *
 */
enum class CipherSuite {
  /**
   * See [RFC 8442](https://tools.ietf.org/html/rfc8442#section-3) for details.
   *
   * **NOTE**: compatibility not tested! openssl 1.1.1 seems not supporting them.
   */
  TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256(
    0xD001,
    CertificateKeyAlgorithm.NONE,
    KeyExchangeAlgorithm.ECDHE_PSK,
    CipherSpec.AES_128_GCM,
    true,
  ),

  /**
   * Wrong cipher suite name! Must be SHA384! Will be changed with the next major version.
   */
  @PublicAPITypo(fixedName = "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384")
  TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA378(
    0xD002,
    CertificateKeyAlgorithm.NONE,
    KeyExchangeAlgorithm.ECDHE_PSK,
    CipherSpec.AES_256_GCM,
    true,
    PRFAlgorithm.TLS_PRF_SHA384,
  ),
  TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256(
    0xD003,
    CertificateKeyAlgorithm.NONE,
    KeyExchangeAlgorithm.ECDHE_PSK,
    CipherSpec.AES_128_CCM_8,
    true,
  ),
  TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256(
    0xD005,
    CertificateKeyAlgorithm.NONE,
    KeyExchangeAlgorithm.ECDHE_PSK,
    CipherSpec.AES_128_CCM,
    true,
  ),

  TLS_PSK_WITH_AES_128_GCM_SHA256(
    0x00A8,
    CertificateKeyAlgorithm.NONE,
    KeyExchangeAlgorithm.PSK,
    CipherSpec.AES_128_GCM,
    true,
  ),

  /**
   * Wrong cipher suite name! Must be SHA384!
   */
  @PublicAPITypo(fixedName = "TLS_PSK_WITH_AES_256_GCM_SHA384")
  TLS_PSK_WITH_AES_256_GCM_SHA378(
    0x00A9,
    CertificateKeyAlgorithm.NONE,
    KeyExchangeAlgorithm.PSK,
    CipherSpec.AES_256_GCM,
    true,
    PRFAlgorithm.TLS_PRF_SHA384,
  ),
  TLS_PSK_WITH_AES_128_CCM_8(
    0xC0A8,
    CertificateKeyAlgorithm.NONE,
    KeyExchangeAlgorithm.PSK,
    CipherSpec.AES_128_CCM_8,
    true,
  ),
  TLS_PSK_WITH_AES_256_CCM_8(
    0xC0A9,
    CertificateKeyAlgorithm.NONE,
    KeyExchangeAlgorithm.PSK,
    CipherSpec.AES_256_CCM_8,
    true,
  ),
  TLS_PSK_WITH_AES_128_CCM(
    0xC0A4,
    CertificateKeyAlgorithm.NONE,
    KeyExchangeAlgorithm.PSK,
    CipherSpec.AES_128_CCM,
    true,
  ),
  TLS_PSK_WITH_AES_256_CCM(
    0xC0A5,
    CertificateKeyAlgorithm.NONE,
    KeyExchangeAlgorithm.PSK,
    CipherSpec.AES_256_CCM,
    true,
  ),

  /**
   * See [RFC 6209 - PSK](https://www.rfc-editor.org/rfc/rfc6209#section-2.3) for details.
   *
   * @since 3.9.0
   */
  TLS_PSK_WITH_ARIA_128_GCM_SHA256(
    0xC06A,
    CertificateKeyAlgorithm.NONE,
    KeyExchangeAlgorithm.PSK,
    CipherSpec.ARIA_128_GCM,
    true,
  ),

  /**
   * See [RFC 6209 - PSK](https://www.rfc-editor.org/rfc/rfc6209#section-2.3) for details.
   *
   * @since 3.9.0
   */
  TLS_PSK_WITH_ARIA_256_GCM_SHA384(
    0xC06B,
    CertificateKeyAlgorithm.NONE,
    KeyExchangeAlgorithm.PSK,
    CipherSpec.ARIA_256_GCM,
    true,
    PRFAlgorithm.TLS_PRF_SHA384,
  ),

  /**See [RFC 5489](https://tools.ietf.org/html/rfc5489#section-3.2) for details*/
  TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256(
    0xC037,
    CertificateKeyAlgorithm.NONE,
    KeyExchangeAlgorithm.ECDHE_PSK,
    CipherSpec.AES_128_CBC,
    MACAlgorithm.HMAC_SHA256,
    false,
  ),
  TLS_PSK_WITH_AES_128_CBC_SHA256(
    0x00AE,
    CertificateKeyAlgorithm.NONE,
    KeyExchangeAlgorithm.PSK,
    CipherSpec.AES_128_CBC,
    MACAlgorithm.HMAC_SHA256,
    false,
  ),

  /**
   * See [RFC 6209 - PSK](https://www.rfc-editor.org/rfc/rfc6209#section-2.3) for details.
   *
   * @since 3.9.0
   */
  TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256(
    0xC06C,
    CertificateKeyAlgorithm.NONE,
    KeyExchangeAlgorithm.ECDHE_PSK,
    CipherSpec.ARIA_128_CBC,
    MACAlgorithm.HMAC_SHA256,
    false,
  ),

  /**
   * See [RFC 6209 - PSK](https://www.rfc-editor.org/rfc/rfc6209#section-2.3) for details.
   *
   * @since 3.9.0
   */
  TLS_PSK_WITH_ARIA_128_CBC_SHA256(
    0xC064,
    CertificateKeyAlgorithm.NONE,
    KeyExchangeAlgorithm.PSK,
    CipherSpec.ARIA_128_CBC,
    MACAlgorithm.HMAC_SHA256,
    false,
  ),

  /**
   * See [RFC 6209 - PSK](https://www.rfc-editor.org/rfc/rfc6209#section-2.3) for details.
   *
   * @since 3.9.0
   */
  TLS_PSK_WITH_ARIA_256_CBC_SHA384(
    0xC065,
    CertificateKeyAlgorithm.NONE,
    KeyExchangeAlgorithm.PSK,
    CipherSpec.ARIA_256_CBC,
    MACAlgorithm.HMAC_SHA384,
    false,
    PRFAlgorithm.TLS_PRF_SHA384,
  ),

  // Certificate cipher suites, ordered by default preference, see getCertificateCipherSuites or getEcdsaCipherSuites
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(
    0xC02B,
    CertificateKeyAlgorithm.EC,
    KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
    CipherSpec.AES_128_GCM,
    true,
  ),
  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384(
    0xC02C,
    CertificateKeyAlgorithm.EC,
    KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
    CipherSpec.AES_256_GCM,
    true,
    PRFAlgorithm.TLS_PRF_SHA384,
  ),
  TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8(
    0xC0AE,
    CertificateKeyAlgorithm.EC,
    KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
    CipherSpec.AES_128_CCM_8,
    true,
  ),
  TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8(
    0xC0AF,
    CertificateKeyAlgorithm.EC,
    KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
    CipherSpec.AES_256_CCM_8,
    true,
  ),
  TLS_ECDHE_ECDSA_WITH_AES_128_CCM(
    0xC0AC,
    CertificateKeyAlgorithm.EC,
    KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
    CipherSpec.AES_128_CCM,
    true,
  ),
  TLS_ECDHE_ECDSA_WITH_AES_256_CCM(
    0xC0AD,
    CertificateKeyAlgorithm.EC,
    KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
    CipherSpec.AES_256_CCM,
    true,
  ),

  /**
   * See [RFC 6209 - GCM](https://www.rfc-editor.org/rfc/rfc6209#section-2.2) for details.
   *
   * @since 3.9.0
   */
  TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256(
    0xC05C,
    CertificateKeyAlgorithm.EC,
    KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
    CipherSpec.ARIA_128_GCM,
    true,
  ),

  /**
   * See [RFC 6209 - GCM](https://www.rfc-editor.org/rfc/rfc6209#section-2.2) for details.
   *
   * @since 3.9.0
   */
  TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384(
    0xC05D,
    CertificateKeyAlgorithm.EC,
    KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
    CipherSpec.ARIA_256_GCM,
    true,
    PRFAlgorithm.TLS_PRF_SHA384,
  ),

  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256(
    0xC023,
    CertificateKeyAlgorithm.EC,
    KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
    CipherSpec.AES_128_CBC,
    MACAlgorithm.HMAC_SHA256,
    false,
  ),
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384(
    0xC024,
    CertificateKeyAlgorithm.EC,
    KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
    CipherSpec.AES_256_CBC,
    MACAlgorithm.HMAC_SHA384,
    false,
    PRFAlgorithm.TLS_PRF_SHA384,
  ),
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA(
    0xC00A,
    CertificateKeyAlgorithm.EC,
    KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
    CipherSpec.AES_256_CBC,
    MACAlgorithm.HMAC_SHA1,
    false,
  ),

  /**
   * See [RFC 6209 - CBC](https://www.rfc-editor.org/rfc/rfc6209#section-2.1) for details.
   *
   * @since 3.9.0
   */
  TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256(
    0xC048,
    CertificateKeyAlgorithm.EC,
    KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
    CipherSpec.ARIA_128_CBC,
    MACAlgorithm.HMAC_SHA256,
    false,
  ),

  /**
   * See [RFC 6209 - CBC](https://www.rfc-editor.org/rfc/rfc6209#section-2.1) for details.
   *
   * @since 3.9.0
   */
  TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384(
    0xC049,
    CertificateKeyAlgorithm.EC,
    KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
    CipherSpec.ARIA_256_CBC,
    MACAlgorithm.HMAC_SHA384,
    false,
    PRFAlgorithm.TLS_PRF_SHA384,
  ),

  // RSA Certificates
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(
    0xC02F,
    CertificateKeyAlgorithm.RSA,
    KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
    CipherSpec.AES_128_GCM,
    true,
  ),
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(
    0xC030,
    CertificateKeyAlgorithm.RSA,
    KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
    CipherSpec.AES_256_GCM,
    true,
    PRFAlgorithm.TLS_PRF_SHA384,
  ),
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256(
    0xC027,
    CertificateKeyAlgorithm.RSA,
    KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
    CipherSpec.AES_128_CBC,
    MACAlgorithm.HMAC_SHA256,
    false,
  ),
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384(
    0xC028,
    CertificateKeyAlgorithm.RSA,
    KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
    CipherSpec.AES_256_CBC,
    MACAlgorithm.HMAC_SHA384,
    false,
    PRFAlgorithm.TLS_PRF_SHA384,
  ),
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(
    0xC014,
    CertificateKeyAlgorithm.RSA,
    KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
    CipherSpec.AES_256_CBC,
    MACAlgorithm.HMAC_SHA1,
    false,
  ),

  /**
   * See [RFC 6209 - GCM](https://www.rfc-editor.org/rfc/rfc6209#section-2.2) for details.
   *
   * @since 3.9.0
   */
  TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256(
    0xC060,
    CertificateKeyAlgorithm.RSA,
    KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
    CipherSpec.ARIA_128_GCM,
    true,
  ),

  /**
   * See [RFC 6209 - GCM](https://www.rfc-editor.org/rfc/rfc6209#section-2.2) for details.
   *
   * @since 3.9.0
   */
  TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384(
    0xC061,
    CertificateKeyAlgorithm.RSA,
    KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
    CipherSpec.ARIA_256_GCM,
    true,
    PRFAlgorithm.TLS_PRF_SHA384,
  ),

  // Null cipher suite
  TLS_NULL_WITH_NULL_NULL(0x0000),

  /**
   * Cipher suite indicating client support for secure renegotiation.
   *
   * Californium doesn't support renegotiation at all, but RFC5746 requests to
   * update to a minimal version of RFC 5746.
   *
   * See [RFC 5746](https://tools.ietf.org/html/rfc5746) for additional details.
   *
   * @see DtlsSecureRenegotiation
   * @since 3.8 (before that only used for logging since 3.5)
   */
  TLS_EMPTY_RENEGOTIATION_INFO_SCSV(0x00FF), ;

  val code: Int
  val isValidForNegotiation: Boolean
  val certificateKeyAlgorithm: CertificateKeyAlgorithm
  val keyExchange: KeyExchangeAlgorithm
  val cipher: CipherSpec
  val macAlgorithm: MACAlgorithm
  val pseudoRandomFunction: PRFAlgorithm
  val maxCipherTextExpansion: Int
  val recommendedCipherSuite: Boolean

  /**
   * Gets the Java Cryptography Architecture _transformation_ corresponding to the suite's underlying cipher
   * algorithm. The name can be used to instantiate a [javax.crypto.Cipher] object (if a security provider is
   * available in the JVM supporting the transformation). See [Java Security Documentation](https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Cipher).
   */
  val transformation: String
    get() = cipher.transformation

  /**
   * Gets the thread local cipher used by this cipher suite.
   */
  val threadLocalCipher: Cipher?
    get() = cipher.cipher

  /**
   * Checks whether this cipher suite requires the server to send a _CERTIFICATE_ message during the handshake.
   */
  val requiresServerCertificateMessage: Boolean
    get() = CertificateKeyAlgorithm.NONE != certificateKeyAlgorithm

  /**
   * Checks whether this cipher suite use _PSK_ key exchange.
   */
  val isPskBased: Boolean
    get() = KeyExchangeAlgorithm.PSK == keyExchange || KeyExchangeAlgorithm.ECDHE_PSK == keyExchange

  /**
   * Checks whether this cipher suite uses elliptic curve cryptography (ECC).
   */
  val isEccBase: Boolean
    get() =
      CertificateKeyAlgorithm.EC == certificateKeyAlgorithm ||
        KeyExchangeAlgorithm.ECDHE_PSK == keyExchange ||
        KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN == keyExchange

  val isSupported: Boolean
    get() = pseudoRandomFunction.macAlgorithm.supported && macAlgorithm.supported && cipher.supported

  /**
   * Check whether this cipher suite is recommended. The recommendation is base one security considerations.
   * Currently AES-CBC is not recommended. Using RSA is also no recommended for performance reasons not for security reasons.
   * Therefore RSA cipher suites may also return `true`.
   */
  val isRecommended: Boolean
    get() = recommendedCipherSuite

  /**
   * Gets the name of the cipher suite's MAC algorithm. The name can be used to instantiate a [javax.crypto.Mac] instance. See [Java Security Documentation](https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Mac).
   */
  val macName: String?
    get() = macAlgorithm.macName

  /**
   * Gets the name of the message digest (hash) function used by the cipher suite MAC. The name can be used
   * to instantiate a [java.security.MessageDigest] instance. See [Java Security Documentation](http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#MessageDigest).
   */
  val messageDigestName: String?
    get() = macAlgorithm.mdName

  /**
   * Gets the thread local MAC used by this cipher suite.
   */
  val threadLocalMac: Mac?
    get() = macAlgorithm.mac

  /**
   * Gets the thread local message digest used by this cipher suite.
   */
  val threadLocalMacMessageDigest: MessageDigest?
    get() = macAlgorithm.messageDigest

  /**
   * Gets the output length of the cipher suite's MAC algorithm.
   */
  val macLength: Int
    get() {
      return if (macAlgorithm == MACAlgorithm.INTRINSIC) {
        cipher.macLength
      } else {
        macAlgorithm.outputLength
      }
    }

  /**
   * Gets the key length of the cipher suite's MAC algorithm.
   */
  val macKeyLength: Int
    get() = macAlgorithm.keyLength

  /**
   * Gets the message block length of hash function.
   */
  val macMessageBlockLength: Int
    get() = macAlgorithm.messageBlockLength

  /**
   * Get the number of bytes used to encode the message length for hmac function.
   */
  val macMessageLengthBytes: Int
    get() = macAlgorithm.messageLengthBytes

  /**
   * Gets the amount of data needed to be generated for the cipher's initialization vector. Zero for stream
   * ciphers; equal to the block size for block ciphers (this is equal to SecurityParameters.record_iv_length).
   */
  val recordIvLength: Int
    get() = cipher.recordIvLength

  /**
   * Gets the length of the fixed initialization vector (IV) of the cipher suite's bulk cipher algorithm. This is only
   * relevant for AEAD based cipher suites.
   */
  val fixedIvLength: Int
    get() = cipher.fixedIvLength

  val pseudoRandomFunctionMacName: String?
    get() = pseudoRandomFunction.macAlgorithm.macName

  val pseudoRandomFunctionMessageDigestName: String?
    get() = pseudoRandomFunction.macAlgorithm.mdName

  val threadLocalPseudoRandomFunctionMac: Mac?
    get() = pseudoRandomFunction.macAlgorithm.mac

  val threadLocalPseudoRandomFunctionMessageDigest: MessageDigest?
    get() = pseudoRandomFunction.macAlgorithm.messageDigest

  val cipherType: CipherType
    get() = cipher.type

  val encKeyLength: Int
    get() = cipher.keyLength

  /**
   * Creates a not negotiable cipher suite.
   * @param code IANA code.
   */
  constructor(code: Int) {
    // CertificateKeyAlgorithm.NONE, KeyExchangeAlgorithm.NULL, CipherSpec.NULL, MACAlgorithm.NULL
    this.code = code
    this.isValidForNegotiation = false
    this.certificateKeyAlgorithm = CertificateKeyAlgorithm.NONE
    this.keyExchange = KeyExchangeAlgorithm.NULL
    this.cipher = CipherSpec.NULL
    this.macAlgorithm = MACAlgorithm.NULL
    this.recommendedCipherSuite = false
    this.pseudoRandomFunction = PRFAlgorithm.TLS_PRF_SHA256
    this.maxCipherTextExpansion = 0
  }

  constructor(
    code: Int,
    certificate: CertificateKeyAlgorithm,
    keyExchange: KeyExchangeAlgorithm,
    cipher: CipherSpec,
    recommendedCipherSuite: Boolean,
  ) : this(
    code,
    certificate,
    keyExchange,
    cipher,
    MACAlgorithm.INTRINSIC,
    recommendedCipherSuite,
    PRFAlgorithm.TLS_PRF_SHA256,
  )

  constructor(
    code: Int,
    certificate: CertificateKeyAlgorithm,
    keyExchange: KeyExchangeAlgorithm,
    cipher: CipherSpec,
    macAlgorithm: MACAlgorithm,
    recommendedCipherSuite: Boolean,
  ) : this(code, certificate, keyExchange, cipher, macAlgorithm, recommendedCipherSuite, PRFAlgorithm.TLS_PRF_SHA256)

  constructor(
    code: Int,
    certificate: CertificateKeyAlgorithm,
    keyExchange: KeyExchangeAlgorithm,
    cipher: CipherSpec,
    recommendedCipherSuite: Boolean,
    prf: PRFAlgorithm,
  ) : this(code, certificate, keyExchange, cipher, MACAlgorithm.INTRINSIC, recommendedCipherSuite, prf)

  constructor(
    code: Int,
    certificate: CertificateKeyAlgorithm,
    keyExchange: KeyExchangeAlgorithm,
    cipher: CipherSpec,
    macAlgorithm: MACAlgorithm,
    recommendedCipherSuite: Boolean,
    prf: PRFAlgorithm,
  ) {
    this.code = code
    this.isValidForNegotiation = true
    this.certificateKeyAlgorithm = certificate
    this.keyExchange = keyExchange
    this.cipher = cipher
    this.macAlgorithm = macAlgorithm
    this.recommendedCipherSuite = recommendedCipherSuite
    this.pseudoRandomFunction = prf
    maxCipherTextExpansion =
      when (this.cipher.type) {
        CipherType.BLOCK -> (
          cipher.recordIvLength + // IV
            macAlgorithm.outputLength + // MAC
            cipher.recordIvLength + // max padding (block size)
            1 // padding length
        )

        CipherType.AEAD -> (
          cipher.recordIvLength + // explicit nonce
            cipher.macLength
        )

        else -> 0
      }
  }

  companion object {
    private val LOGGER: Logger = LoggerFactory.getLogger(CipherSuite::class.java)

    // DTLS-specific constants
    val CIPHER_SUITE_BITS: Int = 16

    val STRONG_ENCRYPTION_PREFERENCE: MutableList<CipherSuite>

    init {
      val secureSuites = arrayListOf<CipherSuite>()
      secureSuites.addAll(
        CipherSuite.getCipherSuitesByKeyExchangeAlgorithm(
          false,
          KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
        ),
      )
      secureSuites.addAll(
        CipherSuite.getCipherSuitesByKeyExchangeAlgorithm(
          false,
          KeyExchangeAlgorithm.ECDHE_PSK,
        ),
      )
      secureSuites.addAll(
        CipherSuite.getCipherSuitesByKeyExchangeAlgorithm(
          false,
          KeyExchangeAlgorithm.PSK,
        ),
      )

      val ccm8 = arrayListOf<CipherSuite>()
      val iterator = secureSuites.iterator()
      while (iterator.hasNext()) {
        val cipherSuite = iterator.next()
        if (cipherSuite.macLength < 16) {
          ccm8.add(cipherSuite)
          iterator.remove()
        }
      }
      secureSuites.addAll(ccm8)
      STRONG_ENCRYPTION_PREFERENCE = Collections.unmodifiableList(secureSuites)
    }

    var overallMaxCipherTextExpansion: Int = 0

    /**
     * Gets the overall maximum ciphertext expansion for all cipher suite.
     * @return overall maximum ciphertext expansion.
     */
    fun getOverallMaxCiphertextExpansion(): Int {
      if (overallMaxCipherTextExpansion == 0) {
        var overall = 0
        entries.forEach { suite ->
          if (suite.isSupported) {
            overall = Math.max(overall, suite.maxCipherTextExpansion)
          }
        }
        overallMaxCipherTextExpansion = overall
      }
      return overallMaxCipherTextExpansion
    }

    /**
     * Get list of supported cipher suites.
     * @param recommendedCipherSuitesOnly `true` to include only recommended cipher suites.
     * @param supportedCipherSuitesOnly `true` to include only supported cipher suites.
     */
    fun getCipherSuites(
      recommendedCipherSuitesOnly: Boolean,
      supportedCipherSuitesOnly: Boolean,
    ): MutableList<CipherSuite> {
      return arrayListOf<CipherSuite>().apply list@{
        entries.forEach { suite ->
          if (suite.isValidForNegotiation) {
            if (!supportedCipherSuitesOnly || suite.isSupported) {
              if (!recommendedCipherSuitesOnly || suite.isRecommended) {
                this@list.add(suite)
              }
            }
          }
        }
      }
    }

    fun getCipherSuitesByKeyExchangeAlgorithm(
      recommendedCipherSuite: Boolean,
      keyExchangeAlgorithm: KeyExchangeAlgorithm,
    ): MutableList<CipherSuite> {
      return getCipherSuitesByKeyExchangeAlgorithm(recommendedCipherSuite, false, arrayListOf(keyExchangeAlgorithm))
    }

    /**
     * Get a list of all cipher suites using the provided key exchange algorithms.
     * @param recommendedCipherSuite `true` use only recommended cipher suites
     * @param keyExchangeAlgorithms list of key exchange algorithms to select cipher suites
     * @return list of all cipher suites. Ordered by their definition above.
     */
    fun getCipherSuitesByKeyExchangeAlgorithm(
      recommendedCipherSuite: Boolean,
      keyExchangeAlgorithms: MutableList<KeyExchangeAlgorithm>?,
    ): MutableList<CipherSuite> {
      requireNotNull(keyExchangeAlgorithms) { "KeyExchangeAlgorithms must not be null!" }
      require(keyExchangeAlgorithms.isNotEmpty()) { "KeyExchangeAlgorithms must not be empty!" }
      return getCipherSuitesByKeyExchangeAlgorithm(recommendedCipherSuite, false, keyExchangeAlgorithms)
    }

    /**
     * Get a list of all cipher suites using the provided key exchange algorithms.
     * @param recommendedCipherSuite `true` use only recommended cipher suites
     * @param orderedByKeyExchangeAlgorithm `true` to order the cipher suites by order of key
     * exchange algorithms, `false` to use the order by their definition above.
     * @param keyExchangeAlgorithms list of key exchange algorithms to select cipher suites
     * @return list of all cipher suites. Ordered as specified by the provided orderedByKeyExchangeAlgorithm
     * @throws NullPointerException if keyExchangeAlgorithm is `null`
     * @throws IllegalArgumentException if keyExchangeAlgorithm is empty
     */
    fun getCipherSuitesByKeyExchangeAlgorithm(
      recommendedCipherSuite: Boolean,
      orderedByKeyExchangeAlgorithm: Boolean,
      keyExchangeAlgorithms: MutableList<KeyExchangeAlgorithm>?,
    ): MutableList<CipherSuite> {
      requireNotNull(keyExchangeAlgorithms) { "KeyExchangeAlgorithms must not be null!" }
      require(keyExchangeAlgorithms.isNotEmpty()) { "KeyExchangeAlgorithms must not be empty!" }
      val list = arrayListOf<CipherSuite>()
      if (orderedByKeyExchangeAlgorithm) {
        keyExchangeAlgorithms.forEach { keyExchange ->
          entries.forEach { suite ->
            if (!recommendedCipherSuite || suite.recommendedCipherSuite) {
              if (suite.isSupported && keyExchange == suite.keyExchange) {
                if (!list.contains(suite)) {
                  list.add(suite)
                }
              }
            }
          }
        }
      } else {
        entries.forEach { suite ->
          if (!recommendedCipherSuite || suite.recommendedCipherSuite) {
            if (suite.isSupported && keyExchangeAlgorithms.contains(suite.keyExchange)) {
              if (!list.contains(suite)) {
                list.add(suite)
              }
            }
          }
        }
      }
      return list
    }

    /**
     * Get a list of all supported cipher suites with the provided key algorithm.
     * @param recommendedCipherSuite `true` use only recommended cipher suites.
     * @param key public key
     * @return list of all supported cipher suites with the provided key algorithm. Ordered by their definition above.
     */
    fun getCertificateCipherSuites(
      recommendedCipherSuite: Boolean,
      key: PublicKey?,
    ): MutableList<CipherSuite> {
      requireNotNull(key) { "Public key must not be null!" }
      val keyAlgorithm = CertificateKeyAlgorithm.getAlgorithm(key)
      val certificateKeyAlgorithms: MutableList<CertificateKeyAlgorithm>? =
        if (keyAlgorithm != null) {
          arrayListOf(keyAlgorithm)
        } else {
          null
        }
      return getCertificateCipherSuites(recommendedCipherSuite, certificateKeyAlgorithms)
    }

    /**
     * Get a list of all supported cipher suites with the provided key algorithms.
     * @param recommendedCipherSuite `true` use only recommended cipher suites
     * @param certificateKeyAlgorithms list of certificate key algorithms
     * @return list of all supported cipher suites with the provided key algorithm. Ordered by their definition above.
     */
    fun getCertificateCipherSuites(
      recommendedCipherSuite: Boolean,
      certificateKeyAlgorithms: MutableList<CertificateKeyAlgorithm>?,
    ): MutableList<CipherSuite> {
      requireNotNull(certificateKeyAlgorithms) { "Certificate key algorithms must not be null!" }
      require(certificateKeyAlgorithms.isNotEmpty()) { "Certificate key algorithms must not be empty!" }
      return arrayListOf<CipherSuite>().apply list@{
        entries.forEach { suite ->
          if (suite.isSupported) {
            if (!recommendedCipherSuite || suite.recommendedCipherSuite) {
              if (certificateKeyAlgorithms.contains(suite.certificateKeyAlgorithm)) {
                this@list.add(suite)
              }
            }
          }
        }
      }
    }

    /**
     * Gets the certificate key algorithms of the cipher suite list.
     * @param cipherSuites list of cipher suite
     */
    fun getCertificateKeyAlgorithms(cipherSuites: MutableList<CipherSuite>): MutableList<CertificateKeyAlgorithm> {
      return arrayListOf<CertificateKeyAlgorithm>().apply types@{
        cipherSuites.forEach { suite ->
          if (suite.certificateKeyAlgorithm != CertificateKeyAlgorithm.NONE) {
            this@types.add(suite.certificateKeyAlgorithm)
          }
        }
      }
    }

    /**
     * Gets a cipher suite by its numeric code.
     * @param code the cipher's [IANA assigned code](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4)
     */
    fun getTypeByCode(code: Int): CipherSuite? {
      entries.forEach { suite ->
        if (suite.code == code) {
          return suite
        }
      }
      if (LOGGER.isTraceEnabled) {
        LOGGER.trace("Cannot resolve cipher suite code [{}]", Integer.toHexString(code))
      }
      return null
    }

    /**
     * Gets a cipher suite by its (official) names.
     * @param name the cipher's [IANA assigned names](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4)
     */
    fun getTypeByName(name: String): CipherSuite? {
      entries.forEach { suite ->
        if (suite.name == name) {
          return suite
        }
      }
      if (LOGGER.isTraceEnabled) {
        LOGGER.trace("Cannot resolve cipher suite code [{}]", name)
      }
      return null
    }

    /**
     * Gets a list of cipher suites by their numeric code.
     * @param names the cipher's [IANA assigned names](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4)
     */
    fun getTypesByNames(names: MutableList<String>): MutableList<CipherSuite> {
      return arrayListOf<CipherSuite>().apply suites@{
        names.forEach { name ->
          val knownSuite = getTypeByName(name)
          if (knownSuite != null) {
            this@suites.add(knownSuite)
          } else {
            throw IllegalArgumentException("Cipher suite [$name] is not (yet) supported")
          }
        }
      }
    }

    /**
     * Checks if a list of cipher suite contains an PSK based cipher.
     * @param cipherSuites the cipher suites to check.
     * @return `true`, if the list contains an PSK based cipher suite, `false`, otherwise.
     */
    fun containsPskBasedCipherSuite(cipherSuites: MutableList<CipherSuite>?): Boolean {
      cipherSuites?.forEach { cipherSuite ->
        if (cipherSuite.isPskBased) {
          return true
        }
      }
      return false
    }

    /**
     * Checks if a list of cipher suite contains an ECC based cipher.
     * @param cipherSuites the cipher suites to check.
     * @return `true`, if the list contains and ECC based cipher suite, `false`, otherwise.
     */
    fun containsEccBasedCipherSuite(cipherSuites: MutableList<CipherSuite>?): Boolean {
      cipherSuites?.forEach { cipherSuite ->
        if (cipherSuite.isEccBase) {
          return true
        }
      }
      return false
    }

    /**
     * Checks if a list of cipher suite contains a cipher suite hat requires the exchange of certificates.
     * @param cipherSuites the cipher suites to check.
     * @return `true` if any of the cipher suites requires the exhcange of certificates, `false` otherwise.
     */
    fun containsCipherSuiteRequiringCertExchange(cipherSuites: MutableList<CipherSuite>?): Boolean {
      cipherSuites?.forEach { cipherSuite ->
        if (cipherSuite.requiresServerCertificateMessage) {
          return true
        }
      }
      return false
    }

    /**
     * Apply preselection to cipher suites. Select (filter) and sort the cipher suites according to the preselection list.
     * @param cipherSuites the cipher suites
     * @param preselect the list of preselected cipher suites
     * @return the selected and sorted list of cipher suites
     * @throws NullPointerException if any of the provided lists is `null`
     * @throws IllegalArgumentException if any of the provided lists is empty.
     */
    fun preselectCipherSuites(
      cipherSuites: MutableList<CipherSuite>?,
      preselect: MutableList<CipherSuite>?,
    ): MutableList<CipherSuite> {
      requireNotNull(cipherSuites) { "The cipher-suites must not be null!" }
      requireNotNull(preselect) { "The preselected cipher-suites must not be null!" }
      require(cipherSuites.isNotEmpty()) { "The cipher-suites must not be empty" }
      require(preselect.isNotEmpty()) { "The preselected cipher-suites must not be empty!" }
      return arrayListOf<CipherSuite>().apply ordered@{
        preselect.forEach { cipherSuite ->
          if (cipherSuite.isValidForNegotiation && cipherSuites.contains(cipherSuite)) {
            this@ordered.add(cipherSuite)
          }
        }
      }
    }

    /**
     * Write a list of cipher suites.
     * @param writer writer to write to
     * @param cipherSuites the cipher suites
     */
    fun listToWriter(
      writer: DatagramWriter,
      cipherSuites: MutableList<CipherSuite>,
    ) {
      cipherSuites.forEach { cipherSuite ->
        writer.write(cipherSuite.code, CIPHER_SUITE_BITS)
      }
    }

    /**
     * Decode cipher suite list from reader.
     * @param reader reader with encoded cipher suites
     * @return list of cipher suites
     * @throws IllegalArgumentException if a decode error occurs
     */
    fun listFromReader(reader: DatagramReader): MutableList<CipherSuite> {
      return arrayListOf<CipherSuite>().apply cipherSuites@{
        while (reader.bytesAvailable()) {
          val code = reader.read(CIPHER_SUITE_BITS)
          val cipher = CipherSuite.getTypeByCode(code)
          // simply ignore unknown cipher suites as mandated by
          // RFC 5246, Section 7.4.1.2 Client Hello
          if (cipher != null) {
            this@cipherSuites.add(cipher)
          }
        }
      }
    }
  }

  enum class CipherSpec(
    val transformation: String,
    val type: CipherType,
    val keyLength: Int,
    val fixedIvLength: Int,
    val recordIvLength: Int,
    val macLength: Int = 0,
  ) {
    // key_length & record_iv_length as documented in RFC 5426, Appendix C
    // see http://tools.ietf.org/html/rfc5246#appendix-C
    NULL("NULL", CipherType.NULL, 0, 0, 0),
    AES_128_CBC(
      "AES/CBC/NoPadding",
      CipherType.BLOCK,
      16,
      0,
      16,
    ), // http://www.ietf.org/mail-archive/web/tls/current/msg08445.html
    AES_256_CBC("AES/CBC/NoPadding", CipherType.BLOCK, 32, 0, 16),
    AES_128_CCM_8(
      AeadBlockCipher.AES_CCM_NO_PADDING,
      CipherType.AEAD,
      16,
      4,
      8,
      8,
    ), // explicit nonce (record IV) length = 8
    AES_256_CCM_8(
      AeadBlockCipher.AES_CCM_NO_PADDING,
      CipherType.AEAD,
      32,
      4,
      8,
      8,
    ), // explicit nonce (record IV) length = 8
    AES_128_CCM(
      AeadBlockCipher.AES_CCM_NO_PADDING,
      CipherType.AEAD,
      16,
      4,
      8,
      16,
    ), // explicit nonce (record IV) length = 8
    AES_256_CCM(
      AeadBlockCipher.AES_CCM_NO_PADDING,
      CipherType.AEAD,
      32,
      4,
      8,
      16,
    ), // explicit nonce (record IV) length = 8
    AES_128_GCM("AES/GCM/NoPadding", CipherType.AEAD, 16, 4, 8, 16), // requires jce implementation of AES/GCM
    AES_256_GCM("AES/GCM/NoPadding", CipherType.AEAD, 32, 4, 8, 16), // requires jce implementation of AES/GCM
    ARIA_128_CBC("ARIA/CBC/NoPadding", CipherType.BLOCK, 16, 0, 16), // requires jce implementation of ARIA/CBC
    ARIA_256_CBC("ARIA/CBC/NoPadding", CipherType.BLOCK, 32, 0, 16), // requires jce implementation of ARIA/CBC
    ARIA_128_GCM("ARIA/GCM/NoPadding", CipherType.AEAD, 16, 4, 8, 16), // requires jce implementation of ARIA/GCM
    ARIA_256_GCM("ARIA/GCM/NoPadding", CipherType.AEAD, 32, 4, 8, 16), // requires jce implementation of ARIA/GCM
    ;

    val supported: Boolean
    private val threadLocalCipher: ThreadLocalCipher?

    /**
     * Gets the thread local cipher used by this cipher specification.
     * @return the cipher, or `null`, if the cipher is not supported by the java-vm.
     */
    val cipher: Cipher?
      get() = threadLocalCipher?.current()

    init {
      var supported = true
      if (type == CipherType.AEAD || type == CipherType.BLOCK) {
        supported = AeadBlockCipher.isSupported(transformation, keyLength)
      }
      if (AeadBlockCipher.AES_CCM_NO_PADDING == transformation) {
        this.threadLocalCipher = null
        this.supported = supported
      } else {
        this.threadLocalCipher = if (supported) ThreadLocalCipher(transformation) else null
        this.supported = this.threadLocalCipher?.isSupported ?: false
      }
    }
  }

  /**
   * Known key exchange algorithm names.
   */
  enum class KeyExchangeAlgorithm {
    NULL,
    DHE_DSS,
    DHE_RSA,
    DH_ANON,
    RSA,
    DH_DSS,
    DH_RSA,
    PSK,
    ECDHE_PSK,
    EC_DIFFIE_HELLMAN,
  }

  enum class PRFAlgorithm(val macAlgorithm: MACAlgorithm) {
    TLS_PRF_SHA256(MACAlgorithm.HMAC_SHA256),
    TLS_PRF_SHA384(MACAlgorithm.HMAC_SHA384),
  }

  /**
   * Known cipher types.
   */
  enum class CipherType {
    NULL,
    STREAM,
    BLOCK,
    AEAD,
  }

  enum class CertificateKeyAlgorithm {
    NONE,
    DSA,
    RSA,
    EC,
    ;

    companion object {
      /**
       * Get algorithm for provided public key.
       * @param key public key to check, May be `null`, which returns [NONE]
       * @return matching algorithm, or `null`, if none is available
       */
      fun getAlgorithm(key: PublicKey?): CertificateKeyAlgorithm? {
        entries.forEach { keyAlgorithm ->
          if (keyAlgorithm.isCompatible(key)) {
            return keyAlgorithm
          }
        }
        return null
      }

      fun getTypeByName(name: String): CertificateKeyAlgorithm? {
        CertificateKeyAlgorithm.entries.forEach { key ->
          if (name == key.name) {
            return key
          }
        }
        if (LOGGER.isTraceEnabled) {
          LOGGER.trace("Cannot resolve certificate key algorithm code [{}]", name)
        }
        return null
      }

      fun getTypesByNames(names: List<String>): MutableList<CertificateKeyAlgorithm> {
        return arrayListOf<CertificateKeyAlgorithm>().apply algorithms@{
          names.forEach { name ->
            val knownAlgorithm = CertificateKeyAlgorithm.getTypeByName(name)
            if (knownAlgorithm != null) {
              this@algorithms.add(knownAlgorithm)
            } else {
              throw IllegalArgumentException("Certificate Key Algorithm [$name] is not (yet) supported")
            }
          }
        }
      }
    }

    /**
     * Checks, if the provided public key is compatible to this algorithm.
     * @param key public key to check. May be `null`, which is considered to be compatible to [NONE].
     * @return `true`, if compatible, `false`, if not
     */
    fun isCompatible(key: PublicKey?): Boolean {
      if (this == NONE) {
        return key == null
      }
      if (key == null) {
        return false
      }
      return isCompatible(key.algorithm)
    }

    /**
     * Checks, if the provided public key algorithm is compatible to this algorithm.
     * @param keyAlgorithm public key algorithm to check.
     * @return `true`, if compatible, `false`, if not
     */
    fun isCompatible(keyAlgorithm: String): Boolean {
      if (keyAlgorithm.equals(name, true)) {
        return true
      }
      if (this == EC) {
        return Asn1DerDecoder.isEcBased(keyAlgorithm)
      }
      return false
    }

    /**
     * Checks, if one of the provided public key algorithms is compatible to this algorithm.
     * @param keyAlgorithms list public key algorithms to check
     * @return `true`, if at least one is compatible, `false`, if none is compatible
     */
    fun isCompatible(keyAlgorithms: MutableList<String>): Boolean {
      keyAlgorithms.forEach { algorithm ->
        if (isCompatible(algorithm)) {
          return true
        }
      }
      return false
    }
  }

  /**
   * See http://tools.ietf.org/html/rfc5246#appendix-A.6
   */
  enum class MACAlgorithm(
    val macName: String?,
    val mdName: String?,
    val outputLength: Int,
    val messageLengthBytes: Int,
    val messageBlockLength: Int,
  ) {
    NULL(null, null, 0, 0, 0),
    INTRINSIC(null, null, 0, 0, 0),
    HMAC_SHA1(
      "HmacSHA1",
      "SHA-1",
      20,
      8,
      64,
    ),
    HMAC_SHA256("HmacSHA256", "SHA-256", 32, 8, 64),
    HMAC_SHA384(
      "HmacSHA384",
      "SHA-384",
      48,
      16,
      128,
    ),
    HMAC_SHA512("HmacSHA512", "SHA-512", 64, 16, 128),
    ;

    val supported: Boolean

    private val threadLocalMac: ThreadLocalMac?
    private val threadLocalMessageDigest: ThreadLocalMessageDigest?

    /**
     * Gets the thread local MAC used by this MAC algorithm.
     * @return mac, or `null`, if not supported by vm.
     */
    val mac: Mac?
      get() = threadLocalMac?.current()

    /**
     * Gets the thread local message digest used by this MAC algorithm. Calls [MessageDigest.reset] on access.
     * @return message digest, or `null`, if not supported by vm.
     */
    val messageDigest: MessageDigest?
      get() = threadLocalMessageDigest?.current()

    val keyLength: Int
      get() = outputLength

    init {
      if (macName == null || mdName == null) {
        this.supported = true
        this.threadLocalMac = null
        this.threadLocalMessageDigest = null
      } else {
        this.threadLocalMac = ThreadLocalMac(macName)
        this.threadLocalMessageDigest = ThreadLocalMessageDigest(mdName)
        this.supported = threadLocalMac.isSupported && threadLocalMessageDigest.isSupported
      }
    }
  }
}
