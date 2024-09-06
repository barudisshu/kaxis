/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.message

import io.kaxis.dtls.ContentType
import io.kaxis.dtls.DTLSMessage
import io.kaxis.dtls.ProtocolVersion
import io.kaxis.exception.HandshakeException
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility
import java.io.Serializable

/**
 * Alert messages convey the severity of the message (warning or fatal) and a description of the alert.
 * Alert messages with a level of fatal result in the immediate termination of the connection. In this case,
 * other connections corresponding to the session may continue, but the session identifier MUST be invalidated.
 * preventing the failed session from being used to establish new connections. Like other messages, alert messages
 * are encrypted and compressed, as specified by the current connection state. For further details see [RFC 5246](https://tools.ietf.org/html/rfc5246#section-7.2).
 */
class AlertMessage(
  val level: AlertLevel,
  val description: AlertDescription,
  val protocolVersion: ProtocolVersion? = null,
) : DTLSMessage, Serializable {
  companion object {
    private const val BITS = 8

    fun fromByteArray(byteArray: ByteArray): AlertMessage {
      val reader = DatagramReader(byteArray)
      val levelCode = reader.readNextByte()
      val descCode = reader.readNextByte()
      val level = AlertLevel.getLevelByCode(levelCode.toInt())
      val description = AlertDescription.getDescriptionByCode(descCode.toInt())
      if (level == null) {
        throw HandshakeException(
          AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR),
          "Unknown alert level code [$levelCode]",
        )
      } else if (description == null) {
        throw HandshakeException(
          AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR),
          "Unknown alert description code [$descCode]",
        )
      } else {
        return AlertMessage(level, description)
      }
    }
  }

  init {
    require(
      !(protocolVersion != null && description != AlertDescription.PROTOCOL_VERSION),
    ) { "Protocol version is only supported for that specific alert!" }
  }

  override val size: Int
    get() = (2 * BITS) / Byte.SIZE_BITS

  override fun toByteArray(): ByteArray {
    val writer = DatagramWriter(2)
    writer.write(level.code, BITS)
    writer.write(description.code, BITS)
    return writer.toByteArray()
  }

  override val contentType: ContentType
    get() = ContentType.ALERT

  override fun toString(indent: Int): String {
    val sb = StringBuilder()
    val indentation = Utility.indentation(indent)
    sb.append(indentation).append("Alert Protocol").append(Utility.LINE_SEPARATOR)
    sb.append(indentation).append("Level: ").append(level).append(Utility.LINE_SEPARATOR)
    sb.append(indentation).append("Description: ").append(description).append(Utility.LINE_SEPARATOR)
    if (protocolVersion != null) {
      sb.append(indentation).append("Protocol Version: ").append(protocolVersion).append(Utility.LINE_SEPARATOR)
    }
    return sb.toString()
  }

  override fun toString(): String {
    return toString(0)
  }

  val isFatal: Boolean
    get() = AlertLevel.FATAL == level

  /**
   * See [Alert Messages](https://tools.ietf.org/html/rfc5246#appendix-A.3) for the listing.
   */
  enum class AlertLevel(val code: Int) {
    WARNING(1),
    FATAL(2),
    ;

    companion object {
      /**
       * Gets the alert level for a given code.
       * @param code the code
       * @return the corresponding level or `null` if no alert level exists for the given code.
       */
      fun getLevelByCode(code: Int): AlertLevel? {
        return when (code) {
          1 -> WARNING
          2 -> FATAL
          else -> null
        }
      }
    }
  }

  /**
   * See [Alert Messages](https://tools.ietf.org/html/rfc5246#appendix-A.3) for the listing.
   */
  enum class AlertDescription(val code: Int, val description: String) {
    CLOSE_NOTIFY(0, "close_notify"),
    UNEXPECTED_MESSAGE(10, "unexpected_message"),
    BAD_RECORD_MAC(20, "bad_record_mac"),
    DECRYPTION_FAILED_RESERVED(21, "decryption_failed"),
    RECORD_OVERFLOW(22, "record_overflow"),
    DECOMPRESSION_FAILURE(30, "decompression_failure"),
    HANDSHAKE_FAILURE(40, "handshake_failure"),
    NO_CERTIFICATE_RESERVED(41, "no_certificate"),
    BAD_CERTIFICATE(42, "bad_certificate"),
    UNSUPPORTED_CERTIFICATE(43, "unsupported_certificate"),
    CERTIFICATE_REVOKED(44, "certificate_revoked"),
    CERTIFICATE_EXPIRED(45, "certificate_expired"),
    CERTIFICATE_UNKNOWN(46, "certificate_unknown"),
    ILLEGAL_PARAMETER(47, "illegal_parameter"),
    UNKNOWN_CA(48, "unknown_ca"),
    ACCESS_DENIED(49, "access_denied"),
    DECODE_ERROR(50, "decode_error"),
    DECRYPT_ERROR(51, "decrypt_error"),
    EXPORT_RESTRICTION_RESERVED(60, "export_restriction"),
    PROTOCOL_VERSION(70, "protocol_version"),
    INSUFFICIENT_SECURITY(71, "insufficient_security"),
    INTERNAL_ERROR(80, "internal_error"),
    USER_CANCELED(90, "user_canceled"),
    NO_RENEGOTIATION(100, "no_negotiation"),
    UNSUPPORTED_EXTENSION(110, "unsupported_extension"),
    UNKNOWN_PSK_IDENTITY(115, "unknown_psk_identity"),
    ;

    companion object {
      /**
       * Gets the alert description for a given code.
       * @param code the code
       * @return the corresponding description or `null`, if no alert description exists for the given code.
       */
      fun getDescriptionByCode(code: Int): AlertDescription? {
        entries.forEach {
          if (it.code == code) {
            return it
          }
        }
        return null
      }
    }
  }
}
