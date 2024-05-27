/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.message.handshake

import io.kaxis.Bytes
import io.kaxis.dtls.*
import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.dtls.cipher.XECDHECryptography
import io.kaxis.dtls.extensions.*
import io.kaxis.dtls.message.AlertMessage
import io.kaxis.exception.HandshakeException
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility
import java.util.*
import javax.crypto.Mac

/**
 * When a client first connects to a server, it is required to send the ClientHello as its first message. The client
 * can also send a ClientHello in response to a [HelloRequest] or on its own initiative in order to re-negotiate the
 * security parameters in an existing connection. See [RFC 5246](https://tools.ietf.org/html/rfc5246#section-7.4.1.2).
 */
class ClientHello : HelloHandshakeMessage {
  companion object {
    private const val COOKIE_LENGTH_BITS = 8

    private const val CIPHER_SUITES_LENGTH_BITS = 16

    private const val COMPRESSION_METHODS_LENGTH_BITS = 8

    /**
     * Creates a new ClientHello instance from its byte representation.
     * @param reader reader with the binary encoding of the message.
     * @return the ClientHello object
     * @throws HandshakeException if any of the extensions included in the message is of an unsupported type
     */
    @Throws(HandshakeException::class)
    fun fromReader(reader: DatagramReader): ClientHello {
      return ClientHello(reader)
    }
  }

  /**
   * The cookie used to prevent flooding attacks (potentially empty).
   */
  var cookie: ByteArray? = null
    set(cookie) {
      requireNotNull(cookie) { "cookie must not be null!" }
      field = cookie.copyOf()
      fragmentChanged()
    }

  /**
   * checks, whether this message contains a cookie.
   * @return `true`, if the message contains a non-empty cookie
   */
  val hasCookie: Boolean
    get() = cookie?.isNotEmpty() ?: false

  /**
   * This is a list of the cryptographic options supported by the client, with the client's first preference first.
   */
  val supportedCipherSuites: MutableList<CipherSuite>

  /**
   * This is a list of the compression methods supported by the client, sorted by client preference.
   */
  val compressionMethods: MutableList<CompressionMethod>
    get() {
      return Collections.unmodifiableList(field)
    }

  /**
   * Creates a _Client Hello_ message to be sent to a server.
   * @param version the protocol version to use
   * @param supportedCipherSuites the list of the supported cipher suites in order of the client's preference (favorite choice first)
   * @param supportedSignatureAndHashAlgorithms the list of the supported signature and hash algorithms
   * @param supportedClientCertificateTypes the list of certificate types supported by the client
   * @param supportedServerCertificateTypes the list of certificate types supported by the server
   * @param supportedGroups the list of the supported groups (curves) in order of the client's preference (favorite choice first)
   */
  constructor(
    version: ProtocolVersion,
    supportedCipherSuites: MutableList<CipherSuite>?,
    supportedSignatureAndHashAlgorithms: MutableList<SignatureAndHashAlgorithm>,
    supportedClientCertificateTypes: MutableList<CertificateType>?,
    supportedServerCertificateTypes: MutableList<CertificateType>?,
    supportedGroups: MutableList<XECDHECryptography.SupportedGroup>,
  ) : this(
    version,
    SessionId.emptySessionId(),
    supportedCipherSuites,
    supportedSignatureAndHashAlgorithms,
    supportedClientCertificateTypes,
    supportedServerCertificateTypes,
    supportedGroups,
  )

  constructor(
    version: ProtocolVersion,
    sessionId: SessionId,
    supportedCipherSuites: MutableList<CipherSuite>?,
    supportedSignatureAndHashAlgorithms: MutableList<SignatureAndHashAlgorithm>,
    supportedClientCertificateTypes: MutableList<CertificateType>?,
    supportedServerCertificateTypes: MutableList<CertificateType>?,
    supportedGroups: MutableList<XECDHECryptography.SupportedGroup>,
  ) : super(version, sessionId) {

    this.cookie = Bytes.EMPTY_BYTES
    this.supportedCipherSuites = arrayListOf()
    if (supportedCipherSuites != null) {
      this.supportedCipherSuites.addAll(supportedCipherSuites)
    }
    this.compressionMethods = arrayListOf()
    // we only need to include elliptic_curves and point_format extensions
    // if the client supports at least one ECC based cipher suite
    if (CipherSuite.containsEccBasedCipherSuite(supportedCipherSuites)) {
      // the supported groups
      addExtension(SupportedEllipticCurvesExtension(supportedGroups))
      // the supported point formats
      addExtension(SupportedPointFormatsExtension.DEFAULT_POINT_FORMATS_EXTENSION)
    }

    // the supported signature and hash algorithms
    if (supportedSignatureAndHashAlgorithms.isNotEmpty()) {
      var ssaa = supportedSignatureAndHashAlgorithms
      if (useCertificateTypeRawPublicKeyOnly(supportedClientCertificateTypes) &&
        useCertificateTypeRawPublicKeyOnly(
          supportedServerCertificateTypes,
        )
      ) {
        if (supportedCipherSuites != null) {
          val certificateKeyAlgorithms = CipherSuite.getCertificateKeyAlgorithms(supportedCipherSuites)
          ssaa = SignatureAndHashAlgorithm.getCompatibleSignatureAlgorithms(ssaa, certificateKeyAlgorithms)
        }
      }
      addExtension(SignatureAlgorithmsExtension(ssaa))
    }

    if (CipherSuite.containsCipherSuiteRequiringCertExchange(supportedCipherSuites)) {
      // the certificate types the client is able to provide to the server
      if (useCertificateTypeExtension(supportedClientCertificateTypes)) {
        val clientCertificateType = ClientCertificateTypeExtension(supportedClientCertificateTypes)
        addExtension(clientCertificateType)
      }
      // the type of certificates the client is able to process when
      // provided
      // by the server
      if (useCertificateTypeExtension(supportedServerCertificateTypes)) {
        val serverCertificateType = ServerCertificateTypeExtension(supportedServerCertificateTypes)
        addExtension(serverCertificateType)
      }
    }
  }

  @Throws(HandshakeException::class)
  private constructor(reader: DatagramReader) : super(reader) {
    cookie = reader.readVarBytes(COOKIE_LENGTH_BITS)

    val cipherSuitesLength = reader.read(CIPHER_SUITES_LENGTH_BITS)
    var rangeReader = reader.createRangeReader(cipherSuitesLength)
    supportedCipherSuites = CipherSuite.listFromReader(rangeReader)

    val compressionMethodsLength = reader.read(COMPRESSION_METHODS_LENGTH_BITS)
    rangeReader = reader.createRangeReader(compressionMethodsLength)
    compressionMethods = CompressionMethod.listFromReader(rangeReader)

    extensions.readFrom(reader)
    val extension = serverNameExtension
    if (extension != null && extension.serverNames == null) {
      throw HandshakeException(
        AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.DECODE_ERROR),
        "ClientHello message contains empty ServerNameExtension",
      )
    }
  }

  /**
   * Check, if certificate type extension is used. If missing, or only contains X_509, don't send the extension.
   * @param supportedCertificateTypes list of certificate types
   * @return `true`, if extension must be used, `false`, otherwise
   */
  private fun useCertificateTypeExtension(supportedCertificateTypes: MutableList<CertificateType>?): Boolean {
    if (!supportedCertificateTypes.isNullOrEmpty()) {
      return supportedCertificateTypes.size > 1 || !supportedCertificateTypes.contains(CertificateType.X_509)
    }
    return false
  }

  /**
   * Check, if only raw public key certificates are used.
   * @param supportedCertificateTypes list of certificate types
   * @return `true`, if only raw public key is used, `false`, otherwise
   */
  private fun useCertificateTypeRawPublicKeyOnly(supportedCertificateTypes: MutableList<CertificateType>?): Boolean {
    if (supportedCertificateTypes != null && supportedCertificateTypes.size == 1) {
      return supportedCertificateTypes.contains(CertificateType.RAW_PUBLIC_KEY)
    }
    return false
  }

  override fun fragmentToByteArray(): ByteArray {
    val writer = DatagramWriter()
    writeHeader(writer)

    writer.writeVarBytes(cookie, COOKIE_LENGTH_BITS)

    writer.write(supportedCipherSuites.size * CipherSuite.CIPHER_SUITE_BITS / Byte.SIZE_BITS, CIPHER_SUITES_LENGTH_BITS)
    CipherSuite.listToWriter(writer, supportedCipherSuites)

    writer.write(compressionMethods.size, COMPRESSION_METHODS_LENGTH_BITS)
    CompressionMethod.listToWriter(writer, compressionMethods)

    extensions.writeTo(writer)
    return writer.toByteArray()
  }

  override fun toString(indent: Int): String {
    val sb = StringBuilder(super.toString(indent))
    val indentation = Utility.indentation(indent + 1)
    val indentation2 = Utility.indentation(indent + 2)
    val ck = cookie
    if (ck != null) {
      sb.append(indentation).append("Cookie Length: ").append(ck.size).append(" bytes")
      if (ck.isNotEmpty()) {
        sb.append(indentation).append("Cookie: ").append(Utility.byteArray2HexString(ck)).append(Utility.LINE_SEPARATOR)
      }
    }
    sb.append(indentation).append("Cipher Suites (").append(supportedCipherSuites.size).append(" suites, ")
      .append(supportedCipherSuites.size * CipherSuite.CIPHER_SUITE_BITS / Byte.SIZE_BITS).append(" bytes)")
      .append(Utility.LINE_SEPARATOR)

    supportedCipherSuites.forEach { cipher ->
      sb.append(indentation2).append("Cipher Suite: ").append(cipher).append(Utility.LINE_SEPARATOR)
    }
    sb.append(indentation).append("Compression Methods (").append(compressionMethods.size).append(" methods, ")
      .append(compressionMethods.size).append(" bytes)").append(Utility.LINE_SEPARATOR)

    compressionMethods.forEach { method ->
      sb.append(indentation2).append("Compression Method: ").append(method).append(Utility.LINE_SEPARATOR)
    }
    sb.append(extensions.toString(indent + 1))
    return sb.toString()
  }

  override val messageType: HandshakeType
    get() = HandshakeType.CLIENT_HELLO

  override val messageLength: Int
    get() {
      // fixed sizes: version (2) + random (32) + session ID length (1) +
      // cookie length (1) + cipher suites length (2) + compression methods
      // length (1) = 39
      // variable sizes: session ID, supported cipher suites, compression
      // methods + extensions
      return (
        39 + sessionId.length() + (cookie?.size ?: 0) +
          supportedCipherSuites.size * CipherSuite.CIPHER_SUITE_BITS / Byte.SIZE_BITS +
          compressionMethods.size +
          extensions.length
      )
    }

  /**
   * Update hmac for cookie generation.
   * @param hmac initialized hamc*
   * @since use no [HelloExtensions] for the cookie, use only the parameter values (version,random,sesion_id,cipher_suites,
   * compression_method). Considering DTLS 1.3 clients, which may vary additional data, including more in the cookie
   * will cause "endless retries" instead of abort the handshake with an alert.
   */
  fun updateForCookie(hmac: Mac) {
    val rawMessage = toByteArray()
    val head =
      sessionId.length() + RANDOM_BYTES + (VERSION_BITS + VERSION_BITS + SESSION_ID_LENGTH_BITS) / Byte.SIZE_BITS
    var tail = head + COOKIE_LENGTH_BITS / Byte.SIZE_BITS + MESSAGE_HEADER_LENGTH_BYTES
    if (cookie != null) {
      tail += cookie!!.size
    }
    val tailLength =
      (
        CIPHER_SUITES_LENGTH_BITS + CIPHER_SUITES_LENGTH_BITS +
          supportedCipherSuites.size * CipherSuite.CIPHER_SUITE_BITS +
          compressionMethods.size * CompressionMethod.COMPRESSION_METHOD_BITS
      ) / Byte.SIZE_BITS

    hmac.update(rawMessage, MESSAGE_HEADER_LENGTH_BYTES, head)
    hmac.update(rawMessage, tail, tailLength)
  }

  /**
   * Get proposed cipher suites.
   * @return list of proposed cipher suites.
   */
  val cipherSuites: MutableList<CipherSuite>
    get() {
      return Collections.unmodifiableList(supportedCipherSuites)
    }

  /**
   * Get list of common cipher suites. List of cipher suites shred by client and server.
   * @param serverCipherSuite server's cipher suites.
   * @return list of common cipher suites
   */
  fun getCommonCipherSuites(serverCipherSuite: MutableList<CipherSuite>): MutableList<CipherSuite> {
    return CipherSuite.preselectCipherSuites(serverCipherSuite, supportedCipherSuites)
  }

  /**
   * Add compression method.
   * @param compressionMethod compression method. Only [CompressionMethod.NULL] is supported.
   */
  fun addCompressionMethod(compressionMethod: CompressionMethod) {
    if (!compressionMethods.contains(compressionMethod)) {
      compressionMethods += (compressionMethod)
    }
  }

  /**
   * Gets the _Server Names_ of the extension data from this message.
   * @return the server names, or `null`, if this message does not contain the _Server Name Indication_ extension.
   */
  val serverNames: ServerNames?
    get() {
      val extension = serverNameExtension
      return extension?.serverNames
    }

  /**
   * Gets the supported elliptic curves.
   * @return the client's supported elliptic curves extension if available, otherwise `null`.
   */
  val supportedEllipticCurvesExtension: SupportedEllipticCurvesExtension?
    get() {
      return extensions[HelloExtension.ExtensionType.ELLIPTIC_CURVES]
    }

  /**
   * Checks, if either the [RenegotiationInfoExtension] or the [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV] is available.
   *
   * Kaxis doesn't support renegotiation at all, but RFC5746 requests to update to a minimal version. See [RFC 5746](https://tools.ietf.org/html/rfc5746) for additional details.
   */
  val hasRenegotiationInfo: Boolean
    get() {
      return hasRenegotiationInfoExtension ||
        supportedCipherSuites.contains(
          CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
        )
    }
}
