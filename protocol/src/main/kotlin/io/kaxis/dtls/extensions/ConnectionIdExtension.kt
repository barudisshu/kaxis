/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.extensions

import io.kaxis.dtls.ConnectionId
import io.kaxis.dtls.message.AlertMessage
import io.kaxis.exception.HandshakeException
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility

class ConnectionIdExtension : HelloExtension {
  companion object {
    private const val CID_FIELD_LENGTH_BITS = 8

    /**
     * Create connection id extension from connection id.
     * @param cid connection id
     * @param type extension type. Must be of type [HelloExtension.ExtensionType.CONNECTION_ID] or the [HelloExtension.ExtensionType.replacement] must be [HelloExtension.ExtensionType.CONNECTION_ID]
     * @return created connection id extension
     * @throws NullPointerException if cid or type is null
     * @throws IllegalArgumentException if type is not [HelloExtension.ExtensionType.CONNECTION_ID] and [HelloExtension.ExtensionType.replacement] is also not [HelloExtension.ExtensionType.CONNECTION_ID]
     */
    fun fromConnectionId(
      cid: ConnectionId?,
      type: ExtensionType?,
    ): ConnectionIdExtension {
      requireNotNull(cid) { "cid must not be null!" }
      requireNotNull(type) { "type must not be null!" }
      require(type == ExtensionType.CONNECTION_ID || type.replacement == ExtensionType.CONNECTION_ID) {
        "$type type is not supported as Connection ID"
      }
      return ConnectionIdExtension(cid, type)
    }

    /**
     * Create connection id extension from extensions data bytes.
     * @param extensionDataReader extension data bytes.
     * @param type extension type. Must be of type [HelloExtension.ExtensionType.CONNECTION_ID] or the [HelloExtension.ExtensionType.replacement] must be [HelloExtension.ExtensionType.CONNECTION_ID].
     * @return created connection id extension
     * @throws NullPointerException if extensionData or type is `null`
     * @throws IllegalArgumentException if type is not [HelloExtension.ExtensionType.CONNECTION_ID] and [HelloExtension.ExtensionType.replacement] is also not [HelloExtension.ExtensionType.CONNECTION_ID].
     * @throws HandshakeException if the extension data could not be decoded.
     */
    fun fromExtensionDataReader(
      extensionDataReader: DatagramReader?,
      type: ExtensionType?,
    ): ConnectionIdExtension {
      requireNotNull(extensionDataReader) { "cid must not be null!" }
      requireNotNull(type) { "type must not be null!" }
      require(type == ExtensionType.CONNECTION_ID || type.replacement == ExtensionType.CONNECTION_ID) {
        "$type type is not supported as Connection ID!"
      }
      val availableBytes = extensionDataReader.bitsLeft() / Byte.SIZE_BITS
      if (availableBytes == 0) {
        throw HandshakeException(
          AlertMessage(
            AlertMessage.AlertLevel.FATAL,
            AlertMessage.AlertDescription.ILLEGAL_PARAMETER,
          ),
          "Connection id length must be provided!",
        )
      } else if (availableBytes > 256) {
        throw HandshakeException(
          AlertMessage(
            AlertMessage.AlertLevel.FATAL,
            AlertMessage.AlertDescription.ILLEGAL_PARAMETER,
          ),
          "Connection id length too large! 255 max, but has ${availableBytes - 1}",
        )
      }
      val len = extensionDataReader.read(CID_FIELD_LENGTH_BITS)
      if (len != (availableBytes - 1)) {
        throw HandshakeException(
          AlertMessage(
            AlertMessage.AlertLevel.FATAL,
            AlertMessage.AlertDescription.ILLEGAL_PARAMETER,
          ),
          "Connection id length $len doesn't match ${availableBytes - 1}!",
        )
      }
      return if (len == 0) {
        ConnectionIdExtension(ConnectionId.EMPTY, type)
      } else {
        val cid = extensionDataReader.readBytes(len)
        ConnectionIdExtension(ConnectionId(cid), type)
      }
    }
  }

  /**
   * Connection id to negotiate.
   */
  val connectionId: ConnectionId

  /**
   * Create connection id extension.
   * @param id connection id
   * @param type [HelloExtension.ExtensionType.CONNECTION_ID], or a type, with that as [HelloExtension.ExtensionType.replacement].
   */
  constructor(id: ConnectionId, type: ExtensionType) : super(type) {
    this.connectionId = id
  }

  /**
   * usage of deprecated definitions. During the specification of [RFC 9146, Connection Identifier for DTLS 1.2](https://www.rfc-editor.org/rfc/rfc9146.html)
   * a deprecated MAC calculation was used along with a also deprecated IANA code point (53) was used before version 09. To support the deprecated version as well,
   * the return value indicates, which MAC variant must be used.
   *
   * @return `true`, if not the current extension ID `54` along with the new MAC calculation is used, `false` otherwise.
   */
  fun useDeprecatedCid(): Boolean = type != ExtensionType.CONNECTION_ID

  override fun toString(indent: Int): String {
    return StringBuilder(super.toString(indent)).apply sb@{
      val indentation = Utility.indentation(indent + 1)
      this@sb.append(indentation).append("DTLS Connection ID: ").append(connectionId).append(Utility.LINE_SEPARATOR)
    }.toString()
  }

  override val extensionLength: Int
    get() {
      // 1 byte cid length + cid
      return (CID_FIELD_LENGTH_BITS / Byte.SIZE_BITS) + connectionId.length()
    }

  override fun writeExtensionTo(writer: DatagramWriter) {
    writer.writeVarBytes(connectionId, CID_FIELD_LENGTH_BITS)
  }
}
