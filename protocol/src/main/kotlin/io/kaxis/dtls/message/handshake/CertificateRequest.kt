/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.message.handshake

import io.kaxis.dtls.HandshakeType
import io.kaxis.dtls.SignatureAndHashAlgorithm
import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.dtls.message.HandshakeMessage
import io.kaxis.util.CertPathUtil
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.PublicKey
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

/**
 * A non-anonymous server can optionally request a certificate from the client, if appropriate for the selected cipher suite.
 *
 * This message, if sent, will immediately follow the [ServerKeyExchange] message (if it is sent; otherwise, this message follows the server's [CertificateMessage] message).
 *
 */
class CertificateRequest : HandshakeMessage {
  companion object {
    private val LOGGER: Logger = LoggerFactory.getLogger(CertificateRequest::class.java)

    // See http://tools.ietf.org/html/rfc5246#section-7.4.4 for message format.

    private const val CERTIFICATE_TYPES_LENGTH_BITS = 8

    private const val CERTIFICATE_TYPE_BITS = 8

    private const val SUPPORTED_SIGNATURE_LENGTH_BITS = 16

    private const val CERTIFICATE_AUTHORITIES_LENGTH_BITS = 16

    private const val CERTIFICATE_AUTHORITY_LENGTH_BITS = 16

    private const val SUPPORTED_SIGNATURE_BITS = 8

    private const val MAX_LENGTH_CERTIFICATE_AUTHORITIES = (1 shl 16) - 1

    /**
     * Parses a certificate request message from its binary encoding.
     * @param reader reader for the binary encoding of the message.
     * @return The parsed instance
     */
    fun fromReader(reader: DatagramReader): CertificateRequest {
      val certificateTypes = arrayListOf<ClientCertificateType>()
      var length = reader.read(CERTIFICATE_TYPES_LENGTH_BITS)
      var rangeReader = reader.createRangeReader(length)
      while (rangeReader.bytesAvailable()) {
        val code = rangeReader.read(CERTIFICATE_TYPE_BITS)
        val clientCertificateType = ClientCertificateType.getTypeByCode(code)
        if (clientCertificateType != null) {
          certificateTypes.add(clientCertificateType)
        }
      }
      val supportedSignatureAlgorithms = arrayListOf<SignatureAndHashAlgorithm>()
      length = reader.read(SUPPORTED_SIGNATURE_LENGTH_BITS)
      rangeReader = reader.createRangeReader(length)
      while (rangeReader.bytesAvailable()) {
        val codeHash = rangeReader.read(SUPPORTED_SIGNATURE_BITS)
        val codeSignature = rangeReader.read(SUPPORTED_SIGNATURE_BITS)
        supportedSignatureAlgorithms.add(SignatureAndHashAlgorithm(codeHash, codeSignature))
      }

      val certificateAuthorities = arrayListOf<X500Principal>()
      length = reader.read(CERTIFICATE_AUTHORITIES_LENGTH_BITS)
      rangeReader = reader.createRangeReader(length)
      while (rangeReader.bytesAvailable()) {
        val name = rangeReader.readVarBytes(CERTIFICATE_AUTHORITY_LENGTH_BITS)
        certificateAuthorities.add(X500Principal(name))
      }
      return CertificateRequest(certificateTypes, supportedSignatureAlgorithms, certificateAuthorities)
    }
  }

  private val certificateTypes: MutableList<ClientCertificateType> = arrayListOf()
  private val supportedSignatureAlgorithms: MutableList<SignatureAndHashAlgorithm> = arrayListOf()
  private val certificateAuthorities: MutableList<X500Principal> = arrayListOf()
  private var certificateAuthoritiesEncodedLength: Int = 0

  /**
   * Create certificate request.
   * @param certificateTypes the list of allowed client certificate types.
   * @param supportedSignatureAlgorithms the list of supported signature and hash algorithms.
   * @param certificateAuthorities the list of allowed certificate authorities.
   */
  constructor(
    certificateTypes: MutableList<ClientCertificateType>? = null,
    supportedSignatureAlgorithms: MutableList<SignatureAndHashAlgorithm>? = null,
    certificateAuthorities: MutableList<X500Principal>? = null,
  ) {
    if (certificateTypes != null) {
      this.certificateTypes.addAll(certificateTypes)
    }
    if (!supportedSignatureAlgorithms.isNullOrEmpty()) {
      this.supportedSignatureAlgorithms.addAll(supportedSignatureAlgorithms)
    }
    if (certificateAuthorities != null) {
      addCertificateAuthorities(certificateAuthorities)
    }
  }

  override val messageType: HandshakeType
    get() = HandshakeType.CERTIFICATE_REQUEST

  override val messageLength: Int
    get() {
      // fixed: certificate type length field (1 byte) + supported signature
      // algorithms length field (2 bytes) + certificate authorities length
      // field (2 bytes) = 5 bytes

      return (
        1 + // certificate type length field
          certificateTypes.size + // each type is represented by 1 byte
          2 + // supported signature algorithms length field
          (supportedSignatureAlgorithms.size * 2) + // each algorithm is represented by 2 bytes
          2 + // certificate authorities length field
          certificateAuthoritiesEncodedLength
      )
    }

  override fun fragmentToByteArray(): ByteArray? {
    val writer = DatagramWriter()

    writer.write(certificateTypes.size, CERTIFICATE_TYPES_LENGTH_BITS)
    certificateTypes.forEach { certificateType ->
      writer.write(certificateType.code, CERTIFICATE_TYPE_BITS)
    }

    writer.write(supportedSignatureAlgorithms.size * 2, SUPPORTED_SIGNATURE_LENGTH_BITS)
    supportedSignatureAlgorithms.forEach { signatureAndHashAlgorithm ->
      writer.write(signatureAndHashAlgorithm.hashAlgorithmCode, SUPPORTED_SIGNATURE_BITS)
      writer.write(signatureAndHashAlgorithm.signatureAlgorithmCode, SUPPORTED_SIGNATURE_BITS)
    }

    writer.write(certificateAuthoritiesEncodedLength, CERTIFICATE_AUTHORITIES_LENGTH_BITS)
    certificateAuthorities.forEach { distinguishedName ->
      // since a distinguished name has variable length, we need to write length field for each name as well, has influence on total length!
      val encoded = distinguishedName.encoded
      writer.writeVarBytes(encoded, CERTIFICATE_AUTHORITY_LENGTH_BITS)
    }

    return writer.toByteArray()
  }

  override fun toString(indent: Int): String {
    return StringBuilder(super.toString(indent)).apply sb@{
    }.toString()
  }

  /**
   * Adds a certificate type to the list of supported certificate types.
   * @param certificateType the type to add.
   */
  fun addCertificateType(certificateType: ClientCertificateType) {
    certificateTypes.add(certificateType)
  }

  /**
   * Adds a certificate key type to the list of supported certificate types.
   * @param certificateKeyAlgorithm the key algorithm to add.
   */
  fun addCertificateType(certificateKeyAlgorithm: CipherSuite.CertificateKeyAlgorithm) {
    ClientCertificateType.entries.forEach { clientCertificateType ->
      if (clientCertificateType.certificateKeyAlgorithm == certificateKeyAlgorithm) {
        addCertificateType(clientCertificateType)
      }
    }
  }

  /**
   * Appends a signature and hash algorithm to the end of the list of supported algorithms.
   *
   * The algorithm's position in list indicates _least preference_ to the recipient (the DTLS client) of the message.
   * @param signatureAndHashAlgorithm The algorithm to add.
   */
  fun addSignatureAlgorithm(signatureAndHashAlgorithm: SignatureAndHashAlgorithm) {
    supportedSignatureAlgorithms.add(signatureAndHashAlgorithm)
  }

  /**
   * Appends a list of signature and hash algorithms to the end of the list of supported algorithms.
   *
   * The algorithm's position in list indicates _least preference_ to the recipient (the DTLS client) of the message.
   * @param signatureAndHashAlgorithms The algorithms to add.
   */
  fun addSignatureAlgorithms(signatureAndHashAlgorithms: List<SignatureAndHashAlgorithm>) {
    supportedSignatureAlgorithms.addAll(signatureAndHashAlgorithms)
  }

  /**
   * Adds a distinguished name to the list of acceptable certificate authorities.
   * @param authority The authority to add.
   * @return `false` if the authority could not be added because it would exceed the maximum encoded length
   * allowed for the certificate request message's certificate authorities vector (2^16-1 bytes).
   * @throws NullPointerException if the authority is `null`
   */
  fun addCertificateAuthority(authority: X500Principal?): Boolean {
    requireNotNull(authority) { "authority must not be null" }
    val encodedAuthorityLength = (
      (CERTIFICATE_AUTHORITY_LENGTH_BITS / Byte.SIZE_BITS) + // length field
        authority.encoded.size
    )
    return if (certificateAuthoritiesEncodedLength + encodedAuthorityLength <= MAX_LENGTH_CERTIFICATE_AUTHORITIES) {
      certificateAuthorities.add(authority)
      certificateAuthoritiesEncodedLength += encodedAuthorityLength
      true
    } else {
      false
    }
  }

  /**
   * Takes a list of trusted certificates, extracts the subject principal and adds the DER-encoded distinguished name
   * to the certificate authorities.
   * @param authorities authorities of the trusted certificates to add.
   * @return `false` if not all certificates could not be added because it would exceed the maximum encoded
   * length allowed for the certificate request message's certificate authorities vector(2^16-1 bytes).
   */
  fun addCertificateAuthorities(authorities: List<X500Principal>): Boolean {
    var authoritiesAdded = 0
    authorities.forEach { authority ->
      if (!addCertificateAuthority(authority)) {
        LOGGER.debug(
          "could add only {} of {} certificate authorities, max length exceeded",
          authoritiesAdded,
          authorities.size,
        )
        return false
      } else {
        authoritiesAdded++
      }
    }
    return true
  }

  /**
   * Gets the certificate key algorithm that the client may offer.
   * @return the certificate key algorithms (never `null`).
   */
  val certificateKeyAlgorithms: List<CipherSuite.CertificateKeyAlgorithm>
    get() {
      return arrayListOf<CipherSuite.CertificateKeyAlgorithm>().apply types@{
        certificateTypes.forEach { type ->
          if (type.certificateKeyAlgorithm != null && !this@types.contains(type.certificateKeyAlgorithm)) {
            this@types.add(type.certificateKeyAlgorithm)
          }
        }
      }
    }

  /**
   * Checks if a given key is compatible with the client certificate types supported by the server.
   * @param key the key
   * @return `true` if the key is compatible.
   */
  fun isSupportedKeyType(key: PublicKey): Boolean {
    val algorithm = key.algorithm
    certificateTypes.forEach { type ->
      if (type.isCompatibleWithKeyAlgorithm(algorithm)) {
        return true
      }
    }
    return false
  }

  /**
   * Checks if a given certificate contains a public key that is compatible with the server's requirements.
   * @param cert The certificate.
   * @return `true` if the certificate's public key is compatible.
   */
  fun isSupportedKeyType(cert: X509Certificate): Boolean {
    var clientUsage: Boolean = false
    val algorithm = cert.publicKey.algorithm
    certificateTypes.forEach goto@{ type ->
      if (!type.isCompatibleWithKeyAlgorithm(algorithm)) {
        LOGGER.debug("type: {}, is not compatible with KeyAlgorithm[{}]", type, algorithm)
        return@goto
      }
      // KeyUsage is an optional extension which may be used to restrict
      // the way the key can be used.
      // https://tools.ietf.org/html/rfc5280#section-4.2.1.3
      // If this extension is used, we check if digitalsignature usage is
      // present.
      // (For more details see :
      // https://github.com/eclipse/californium/issues/748)
      if (type.requiresSigningCapability) {
        if (!clientUsage) {
          clientUsage = CertPathUtil.canBeUsedForAuthentication(cert, true)
        }
        if (!clientUsage) {
          LOGGER.debug("type: {}, requires missing signing capability!", type)
          return@goto
        }
      }
      LOGGER.debug("type: {}, is compatible with KeyAlgorithm[{}] and meets signing requirements", type, algorithm)
      return true
    }
    LOGGER.debug("certificate [{}] with public key {} is not of any supported type", cert, algorithm)
    return false
  }

  /**
   * Gets the signature algorithm that is compatible with a given public key.
   * @param key The public key.
   * @param clientSupportedSignatureAlgorithms The signature algorithms supported by the client.
   * @return A signature algorithm that can be used with the given key or `null` if the given key is not compatible with
   * any of the supported certificate types or any of the supported signature algorithms.
   */
  fun getSignatureAndHashAlgorithm(
    key: PublicKey,
    clientSupportedSignatureAlgorithms: MutableList<SignatureAndHashAlgorithm>,
  ): SignatureAndHashAlgorithm? {
    if (isSupportedKeyType(key)) {
      val negotiated =
        SignatureAndHashAlgorithm.getCommonSignatureAlgorithms(
          supportedSignatureAlgorithms,
          clientSupportedSignatureAlgorithms,
        )
      return SignatureAndHashAlgorithm.getSupportedSignatureAlgorithm(negotiated, key)
    }
    return null
  }

  /**
   * Gets a signature algorithm that is compatible with a given certificate chain.
   * @param chain The certificate chain.
   * @param clientSupportedSignatureAlgorithms The signature algorithms supported by the client.
   * @return A signature algorithm that can be used with the key contained in the given chain's end entity
   * certificate or `null` if any of the chain's certificates is not compatible with any of the supported
   * certificate types or any of the supported signature algorithms.
   */
  fun getSignatureAndHashAlgorithm(
    chain: MutableList<X509Certificate>,
    clientSupportedSignatureAlgorithms: MutableList<SignatureAndHashAlgorithm>,
  ): SignatureAndHashAlgorithm? {
    val certificate = chain[0]
    if (isSupportedKeyType(certificate)) {
      val negotiated =
        SignatureAndHashAlgorithm.getCommonSignatureAlgorithms(
          supportedSignatureAlgorithms,
          clientSupportedSignatureAlgorithms,
        )
      val signatureAndHashAlgorithm =
        SignatureAndHashAlgorithm.getSupportedSignatureAlgorithm(negotiated, certificate.publicKey)
      // use the signature algorithms of the other peer to check the chain.
      // only the other peer verifies the signatures of the chain
      if (signatureAndHashAlgorithm != null &&
        SignatureAndHashAlgorithm.isSignedWithSupportedAlgorithms(
          supportedSignatureAlgorithms,
          chain,
        )
      ) {
        return signatureAndHashAlgorithm
      }
    }
    return null
  }

  /**
   * Certificate types that the client may offer. See [RFC 5246](https://tools.ietf.org/html/rfc5246#section-7.4.4) for details.
   */
  enum class ClientCertificateType(
    val code: Int,
    val certificateKeyAlgorithm: CipherSuite.CertificateKeyAlgorithm? = null,
  ) {
    RSA_SIGN(1, CipherSuite.CertificateKeyAlgorithm.RSA),
    DSS_SIGN(2, CipherSuite.CertificateKeyAlgorithm.DSA),
    RSA_FIXED_DH(3),
    DSS_FIXED_DH(4),
    RSA_EPHEMERAL_DH_RESERVED(5),
    DSS_EPHEMERAL_DH_RESERVED(6),
    FORTEZZA_DMS_RESERVED(20),
    ECDSA_SIGN(64, CipherSuite.CertificateKeyAlgorithm.EC),
    RSA_FIXED_ECDH(65),
    ECDSA_FIXED_ECDH(66),
    ;

    companion object {
      /**
       * Gets a certificate type by its code as defined by [RFC 5246, Section 7.4.4](https://tools.ietf.org/html/rfc5246#section-7.4.4).
       * @param code the code
       * @return the certificate type or `null` if the given code is not defined.
       */
      fun getTypeByCode(code: Int): ClientCertificateType? {
        entries.forEach { type ->
          if (type.code == code) {
            return type
          }
        }
        return null
      }
    }

    /**
     * Indicates whether this certificate type requires the key to allow being used for signing.
     */
    val requiresSigningCapability: Boolean
      get() = certificateKeyAlgorithm != null

    /**
     * Check if this certificate type is compatible with a given JCA standard key algorithm.
     * @param algorithm The key algorithm
     * @return `true` if this certificate type is compatible with the given key algorithm.
     */
    fun isCompatibleWithKeyAlgorithm(algorithm: String): Boolean {
      return certificateKeyAlgorithm?.isCompatible(algorithm) ?: false
    }
  }
}
