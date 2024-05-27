/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.extensions

import io.kaxis.dtls.message.AlertMessage
import io.kaxis.exception.HandshakeException
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * An abstract class representing the functionality for all possible defined extensions.
 *
 * See [RFC 5246](https://tools.ietf.org/html/rfc5246#section-7.4.1.4) for the extension format.
 *
 * In particular this class is an object representation of the _Extension_ struct defined in [TLS 1.2, Section 7.4.1.4](https://tools.ietf.org/html/rfc5246#section-7.4.1.4).
 *
 * ```c
 *  struct {
 *    ExtensionType extension_type;
 *    opaque extension_data<0..2^16-1>;
 *  } Extension;
 *
 *  enum {
 *    signature_algorithms(13), (65535)
 *  } ExtensionType;
 * ```
 *
 */
abstract class HelloExtension(val type: ExtensionType) {
  companion object {
    private val LOGGER: Logger = LoggerFactory.getLogger(HelloExtension::class.java)

    const val TYPE_BITS = 16
    const val LENGTH_BITS = 16

    /**
     * De-serializes a Client or Server Hello handshake message extension form its binary representation. The TLS
     * spec is unspecific about how a server should handle extensions sent by a client that it does not
     * understand. However, [Section 4.2 of RFC 7250](https://tools.ietf.org/html/rfc7250#section-4.2) mandates that a server implementation must simply
     * ignore extensions of type _client_certificate_type_ or _server_certificate_type_ if it does not support these
     * extensions. This (lenient) approach seems feasible for the server to follow in general when a client sends
     * an extension of a type that the server does not know or support (yet).
     * @param reader the serialized extension
     * @return the object representing the extension or `null`, if the extension type is not (yet) known to or supported.
     * @throws HandshakeException if the (supported) extension could not be deserialized, e.g. due to erroneous encoding etc.
     *
     */
    @Throws(HandshakeException::class)
    fun readFrom(reader: DatagramReader): HelloExtension? {
      val typeId = reader.read(TYPE_BITS)
      val extensionLength = reader.read(LENGTH_BITS)
      val extensionDataReader = reader.createRangeReader(extensionLength)
      val type = ExtensionType.getExtensionTypeById(typeId)
      var extension: HelloExtension? = null
      if (type != null) {
        when (type) {
          // the currently supported extensions
          ExtensionType.ELLIPTIC_CURVES ->
            extension =
              SupportedEllipticCurvesExtension.fromExtensionDataReader(extensionDataReader)

          ExtensionType.EC_POINT_FORMATS ->
            extension =
              SupportedPointFormatsExtension.fromExtensionDataReader(extensionDataReader)

          ExtensionType.SIGNATURE_ALGORITHMS ->
            extension =
              SignatureAlgorithmsExtension.fromExtensionDataReader(extensionDataReader)

          ExtensionType.CLIENT_CERT_TYPE ->
            extension =
              ClientCertificateTypeExtension.fromExtensionDataReader(extensionDataReader)

          ExtensionType.SERVER_CERT_TYPE ->
            extension =
              ServerCertificateTypeExtension.fromExtensionDataReader(extensionDataReader)

          ExtensionType.MAX_FRAGMENT_LENGTH ->
            extension =
              MaxFragmentLengthExtension.fromExtensionDataReader(extensionDataReader)

          ExtensionType.SERVER_NAME -> extension = ServerNameExtension.fromExtensionDataReader(extensionDataReader)
          ExtensionType.RECORD_SIZE_LIMIT ->
            extension =
              RecordSizeLimitExtension.fromExtensionDataReader(extensionDataReader)

          ExtensionType.EXTENDED_MASTER_SECRET ->
            extension =
              ExtendedMasterSecretExtension.fromExtensionDataReader(extensionDataReader)

          ExtensionType.CONNECTION_ID ->
            extension =
              ConnectionIdExtension.fromExtensionDataReader(extensionDataReader, type)

          ExtensionType.RENEGOTIATION_INFO ->
            extension =
              RenegotiationInfoExtension.fromExtensionDataReader(extensionDataReader)

          else -> {
            if (type.replacement == ExtensionType.CONNECTION_ID) {
              extension = ConnectionIdExtension.fromExtensionDataReader(extensionDataReader, type)
            }
          }
        }
      }
      if (extension != null) {
        if (extensionDataReader.bytesAvailable()) {
          val bytesLeft = extensionDataReader.readBytesLeft()
          throw HandshakeException(
            AlertMessage(
              AlertMessage.AlertLevel.FATAL,
              AlertMessage.AlertDescription.DECODE_ERROR,
            ),
            "Too many bytes, ${bytesLeft.size} left, " +
              "hello extension not completely parsed! hello extension type $typeId",
          )
        }
      } else {
        extensionDataReader.close()
      }
      return extension
    }
  }

  /**
   * Gets the length of this extension's corresponding _Extension_ struct.
   *
   * **NOTE:** that this doesn't include the 2 bytes indicating the extension type nor the 2 bytes for the length.
   * @return the length in bytes
   */
  abstract val extensionLength: Int

  val length: Int
    get() = ((TYPE_BITS + LENGTH_BITS) / Byte.SIZE_BITS) + extensionLength

  /**
   * Serializes this extension to its byte representation as specified by its respective RFC.
   *
   * The extension code and length are already serialized.
   * @param writer writer to write extension to.
   */
  abstract fun writeExtensionTo(writer: DatagramWriter)

  fun writeTo(writer: DatagramWriter) {
    writer.write(type.id, TYPE_BITS)
    writer.write(extensionLength, LENGTH_BITS)
    writeExtensionTo(writer)
  }

  /**
   * Gets the textual presentation of this message.
   * @param indent line indentation
   * @return textual presentation
   */
  open fun toString(indent: Int): String {
    return StringBuilder().apply sb@{
      val indentation = Utility.indentation(indent)
      this@sb.append(indentation).append("Extension: ").append(type).append(" (").append(type.id).append("), ")
        .append(extensionLength).append(" bytes").append(Utility.LINE_SEPARATOR)
    }.toString()
  }

  override fun toString(): String {
    return toString(0)
  }

  /**
   * The possible extension types (defined in multiple documents). See [IANA](http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xml) for a summary.
   */
  enum class ExtensionType(val id: Int, val desc: String, val replacement: ExtensionType? = null) {
    // See https://tools.ietf.org/html/rfc6066
    SERVER_NAME(0, "server_name"),
    MAX_FRAGMENT_LENGTH(1, "max_fragment_length"),
    CLIENT_CERTIFICATE_URL(2, "client_certificate_url"),
    TRUSTED_CA_KEYS(3, "trusted_ca_keys"),
    TRUNCATED_HMAC(4, "truncated_hmac"),
    STATUS_REQUEST(5, "status_request"),

    /**
     * See [RFC 4681](https://tools.ietf.org/html/rfc4681)
     */
    USER_MAPPING(6, "user_mapping"),

    /**
     * See [RFC 5878](https://www.iana.org/go/rfc5878)
     */
    CLIENT_AUTHZ(7, "client_authz"),
    SERVER_AUTHZ(8, "server_authz"),

    /**
     * See [TLS Out-of-Band Public Key Validation](https://tools.ietf.org/html/draft-ietf-tls-oob-pubkey-03#section-3.1)
     */
    CERT_TYPE(9, "cert_type"),

    /**
     * See [RFC 4492](https://tools.ietf.org/html/rfc4492#section-5.1)
     */
    ELLIPTIC_CURVES(10, "elliptic_curves"),
    EC_POINT_FORMATS(11, "ec_point_formats"),

    /**
     * See [RFC 5054](https://www.iana.org/go/rfc5054)
     */
    SRP(12, "srp"),

    /** See [RFC 5246](https://www.iana.org/go/rfc5246) */
    SIGNATURE_ALGORITHMS(13, "signature_algorithms"),

    /**
     * See [RFC 5764](https://www.iana.org/go/rfc5764)
     */
    USE_SRTP(14, "use_srtp"),

    /**
     * See [RFC 6520](https://www.iana.org/go/rfc6520)
     */
    HEARTBEAT(15, "heartbeat"),

    /**
     * See [draft-friedl-tls-applayerprotoneg](https://www.iana.org/go/draft-friedl-tls-applayerprotoneg)
     */
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION(16, "application_layer_protocol_negotiation"),

    /**
     * See [draft-ietf-tls-multiple-cert-status-extension-08](https://www.iana.org/go/draft-ietf-tls-multiple-cert-status-extension-08)
     */
    STATUS_REQUEST_V2(17, "status_request_v2"),

    /**
     * See [draft-laurie-pki-sunlight-12](https://www.iana.org/go/draft-laurie-pki-sunlight-12)
     */
    SIGNED_CERTIFICATE_TIMESTAMP(18, "signed_certificate_timestamp"),

    /**
     * See [RFC 7250](https://tools.ietf.org/html/rfc7250)
     */
    CLIENT_CERT_TYPE(19, "client_certificate_type"),
    SERVER_CERT_TYPE(20, "server_certificate_type"),

    /**
     * See [RFC 7366](https://www.iana.org/go/rfc7366)
     **/
    ENCRYPT_THEN_MAC(22, "encrypt_then_mac"),

    /**
     * See [RFC 7627](https://tools.ietf.org/html/rfc7627)
     *
     * @since 3.0
     **/
    EXTENDED_MASTER_SECRET(23, "extended_master_secret"),

    /**
     * See [RFC 8449](https://tools.ietf.org/html/rfc8449)
     *
     * @since 2.4
     **/
    RECORD_SIZE_LIMIT(28, "record_size_limit"),

    /**
     * See [RFC 4507](https://www.iana.org/go/rfc4507)
     **/
    SESSION_TICKET_TLS(35, "SessionTicket TLS"),

    /**
     * See [RFC 9146, Connection Identifier for DTLS 1.2](https://www.rfc-editor.org/rfc/rfc9146.html) and
     * [IANA TLS ExtensionType Values](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1)
     *
     * @since 3.0
     **/
    CONNECTION_ID(54, "Connection ID"),

    /**
     * See [RFC 9146, Connection Identifier for DTLS 1.2](https://www.rfc-editor.org/rfc/rfc9146.html) and
     * [IANA code point assignment](https://mailarchive.ietf.org/arch/msg/tls/3wCyihI6Y7ZlciwcSDaQ322myYY)
     *
     * **Note:** Before version 09 of the specification, the value 53 was
     * used for the extension along with a different calculated MAC.
     *
     * **Note:** to support other, proprietary code points, just clone
     * this, using the proprietary code points, a different description and
     * a different name, e.g.:
     *
     * ```
     * CONNECTION_ID_MEDTLS(254, "Connection ID (mbedtls)", CONNECTION_ID),
     * ```
     *
     * @since 3.0
     **/
    CONNECTION_ID_DEPRECATED(53, "Connection ID (deprecated)", CONNECTION_ID),

    /**
     * See [RFC 5746](https://www.iana.org/go/rfc5746)
     **/
    RENEGOTIATION_INFO(65281, "renegotiation_info"),
    ;

    companion object {
      /**
       * Gets an extension type by its numeric id as defined by [IANA](http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xml)
       * @param id the numeric id of the extension
       * @return the corresponding extension type or `null`, if the given id is unsupported.
       */
      fun getExtensionTypeById(id: Int): ExtensionType? = entries.firstOrNull { it.id == id }
    }

    override fun toString(): String {
      return desc
    }
  }
}
