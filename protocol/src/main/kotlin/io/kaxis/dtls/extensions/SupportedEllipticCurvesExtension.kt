/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.extensions

import io.kaxis.dtls.cipher.XECDHECryptography
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility
import java.util.*

/**
 * The supported elliptic curves extension.
 *
 * According [RFC 8422, 5.1.1. Supported Elliptic Curves Extension](https://tools.ietf.org/html/rfc8422#section-5.1.1) only
 * "named curves" are valid, the "prime" and "char2" curve descriptions are deprecated.
 */
class SupportedEllipticCurvesExtension(val supportedGroups: List<XECDHECryptography.SupportedGroup>) :
  HelloExtension(ExtensionType.ELLIPTIC_CURVES) {
  companion object {
    private const val LIST_LENGTH_BITS = 16

    private const val CURVE_BITS = 16

    fun fromExtensionDataReader(extensionDataReader: DatagramReader): SupportedEllipticCurvesExtension {
      val groups = mutableListOf<XECDHECryptography.SupportedGroup>()
      val listLength = extensionDataReader.read(LIST_LENGTH_BITS)
      val rangeReader = extensionDataReader.createRangeReader(listLength)
      while (rangeReader.bytesAvailable()) {
        val id = rangeReader.read(CURVE_BITS)
        val group = XECDHECryptography.SupportedGroup.fromId(id)
        if (group != null) {
          groups.add(group)
        }
      }
      return SupportedEllipticCurvesExtension(Collections.unmodifiableList(groups))
    }
  }

  override fun toString(indent: Int): String {
    return StringBuilder(super.toString(indent)).apply sb@{
      val indentation = Utility.indentation(indent + 1)
      val indentation2 = Utility.indentation(indent + 2)
      this@sb.append(indentation).append("Elliptic Curves (").append(supportedGroups.size).append(" curves):")
        .append(Utility.LINE_SEPARATOR)
      supportedGroups.forEach { group ->
        this@sb.append(indentation2).append("Elliptic Curve: ").append(group.name).append(" (").append(group.id)
          .append(")").append(Utility.LINE_SEPARATOR)
      }
    }.toString()
  }

  override val extensionLength: Int
    get() {
      // fixed: list length (2 bytes)
      // variable: number of named curves * 2 (2 bytes for each curve)
      return (LIST_LENGTH_BITS / Byte.SIZE_BITS) + (supportedGroups.size * (CURVE_BITS / Byte.SIZE_BITS))
    }

  override fun writeExtensionTo(writer: DatagramWriter) {
    val listLength = supportedGroups.size * (CURVE_BITS / Byte.SIZE_BITS)
    writer.write(listLength, LIST_LENGTH_BITS)
    supportedGroups.forEach { group ->
      writer.write(group.id, CURVE_BITS)
    }
  }
}
