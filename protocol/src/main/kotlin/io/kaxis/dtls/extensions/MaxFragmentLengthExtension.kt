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

/**
 * An object representation of the _MaxFragmentLength_ extension for the _Transport Level Security_ protocol.
 *
 * Instances of this class can be serialized to and deserialized from the _MaxFragmentLength_ data structure defined in [RFC 6066, Section 4](https://tools.ietf.org/html/rfc6066#section-4).
 */
class MaxFragmentLengthExtension(val fragmentLength: Length) : HelloExtension(ExtensionType.MAX_FRAGMENT_LENGTH) {
  companion object {
    const val CODE_BITS = 8

    /**
     * Creates an instance from a _MaxFragmentLength_ structure as defined in [RFC 6066, Section 4](https://tools.ietf.org/html/rfc6066#section-4).
     * @param extensionDataReader the extension data struct containing the length code
     * @return the extension object
     * @throws HandshakeException if the extension data contains an unknown code
     */
    @Throws(HandshakeException::class)
    fun fromExtensionDataReader(extensionDataReader: DatagramReader): MaxFragmentLengthExtension {
      val code = extensionDataReader.read(CODE_BITS)
      val length = Length.fromCode(code)
      if (length != null) {
        return MaxFragmentLengthExtension(length)
      } else {
        throw HandshakeException(
          AlertMessage(
            AlertMessage.AlertLevel.FATAL,
            AlertMessage.AlertDescription.ILLEGAL_PARAMETER,
          ),
          "Peer uses unknown code [$code] in ${ExtensionType.MAX_FRAGMENT_LENGTH.name} extension",
        )
      }
    }
  }

  override val extensionLength: Int
    get() {
      // fixed: 1 byte (extension data)
      return CODE_BITS / Byte.SIZE_BITS
    }

  override fun writeExtensionTo(writer: DatagramWriter) {
    writer.write(fragmentLength.code, CODE_BITS)
  }

  override fun toString(indent: Int): String {
    return StringBuilder(super.toString(indent)).apply sb@{
      val indentation = Utility.indentation(indent + 1)
      this@sb.append(indentation).append("code: ").append(fragmentLength.code).append(" (")
        .append(fragmentLength.length).append(" bytes)").append(Utility.LINE_SEPARATOR)
    }.toString()
  }

  /**
   * The codes representing the lengths that can be negotiated using the _Max Fragment Length_ Hello extension.
   */
  enum class Length(val code: Int, val length: Int) {
    BYTES_512(1, 512),
    BYTES_1024(2, 1024),
    BYTES_2048(3, 2048),
    BYTES_4096(4, 4096),
    ;

    companion object {
      /**
       * Creates an instance from its code.
       * @param code the code
       * @return the instance or `null`, if the given code is unknown
       */
      fun fromCode(code: Int): Length? {
        return when (code) {
          1 -> BYTES_512
          2 -> BYTES_1024
          3 -> BYTES_2048
          4 -> BYTES_4096
          else -> null
        }
      }

      /**
       * Creates an instance from its value.
       * @param length the length
       * @return the instance or `null`, if the given length is mismatched
       */
      fun fromValue(length: Int): Length? {
        return when (length) {
          512 -> BYTES_512
          1024 -> BYTES_1024
          2048 -> BYTES_2048
          4096 -> BYTES_4096
          else -> null
        }
      }
    }
  }
}
