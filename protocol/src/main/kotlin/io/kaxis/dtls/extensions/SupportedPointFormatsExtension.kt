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

import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility
import java.util.*

/**
 * The supported point formats extension.
 *
 * According [RFC 8422, 5.1.1. Supported Elliptic Curves Extension](https://tools.ietf.org/html/rfc8422#section-5.1.1) only "UNCOMPRESSED" as point
 * format is valid, the other formats have been deprecated.
 */
class SupportedPointFormatsExtension(val ecPointFormatList: List<ECPointFormat>) :
  HelloExtension(ExtensionType.EC_POINT_FORMATS) {
  companion object {
    private const val LIST_LENGTH_BITS = 8

    private const val POINT_FORMAT_BITS = 8

    private val EC_POINT_FORMATS = Collections.singletonList(ECPointFormat.UNCOMPRESSED)

    /**
     * Default ec point format extension.
     */
    val DEFAULT_POINT_FORMATS_EXTENSION = SupportedPointFormatsExtension(EC_POINT_FORMATS)

    fun fromExtensionDataReader(extensionDataReader: DatagramReader): SupportedPointFormatsExtension {
      val ecPointFormatList = arrayListOf<ECPointFormat>()
      val listLength = extensionDataReader.read(LIST_LENGTH_BITS)
      val rangeReader = extensionDataReader.createRangeReader(listLength)
      while (rangeReader.bytesAvailable()) {
        val format = ECPointFormat.getECPointFormatById(rangeReader.read(POINT_FORMAT_BITS))
        if (format != null) {
          ecPointFormatList.add(format)
        }
      }
      return if (ecPointFormatList.size == 1 && ecPointFormatList.contains(ECPointFormat.UNCOMPRESSED)) {
        DEFAULT_POINT_FORMATS_EXTENSION
      } else {
        SupportedPointFormatsExtension(ecPointFormatList)
      }
    }
  }

  fun contains(format: ECPointFormat): Boolean = ecPointFormatList.contains(format)

  override fun toString(indent: Int): String {
    return StringBuilder(super.toString(indent)).apply sb@{
      val indentation = Utility.indentation(indent + 1)
      val indentation2 = Utility.indentation(indent + 2)
      this@sb.append(indentation).append("Elliptic Curves Point Formats (").append(ecPointFormatList.size)
        .append(" formats):").append(Utility.LINE_SEPARATOR)
      ecPointFormatList.forEach { format ->
        this@sb.append(indentation2).append("EC point format: ").append(format).append(Utility.LINE_SEPARATOR)
      }
    }.toString()
  }

  override val extensionLength: Int
    get() {
      // fixed: list length (1 byte)
      // variable: number of point formats
      return 1 + ecPointFormatList.size
    }

  override fun writeExtensionTo(writer: DatagramWriter) {
    // list length + list length field (1 byte)
    writer.write(ecPointFormatList.size, LIST_LENGTH_BITS)
    ecPointFormatList.forEach { format ->
      writer.write(format.id, POINT_FORMAT_BITS)
    }
  }

  /**
   * See [RFC 4492, 5.1.2. Supported Point Formats Extension](https://tools.ietf.org/html/rfc4492#section-5.1.2).
   */
  enum class ECPointFormat(val id: Int) {
    UNCOMPRESSED(0),
    ANSIX962_COMPRESSED_PRIME(1),
    ANSIX962_COMPRESSED_CHAR2(2),
    ;

    companion object {
      fun getECPointFormatById(id: Int): ECPointFormat? {
        return when (id) {
          0 -> UNCOMPRESSED
          1 -> ANSIX962_COMPRESSED_PRIME
          2 -> ANSIX962_COMPRESSED_CHAR2
          else -> null
        }
      }
    }

    override fun toString(): String {
      return when (id) {
        0 -> "uncompressed (0)"
        1 -> "ansiX962_compressed_prime(1)"
        2 -> "ansiX962_compressed_char2(2)"
        else -> ""
      }
    }
  }
}
