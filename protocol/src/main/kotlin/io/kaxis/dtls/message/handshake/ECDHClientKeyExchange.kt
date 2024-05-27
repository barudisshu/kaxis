/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.message.handshake

import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility

/**
 * [ClientKeyExchange] message for all ECDH based key exchange methods. Contains the client's ephemeral
 * public key as encoded point. See [RFC 4492](https://tools.ietf.org/html/rfc4492#section-5.7) for further details. It is assumed, that the client's ECDH public key
 * is not in the client's certificate, so it must be provided here.
 *
 * According [RFC 8422, 5.1.1. Supported Elliptic Curves Extension](https://tools.ietf.org/html/rfc8422#section-5.1.1) only "named curves" are valid, the "prime"
 * and "char2" curve descriptions are deprecated. Also only "UNCOMPRESSED" as point format is valid, the other formats
 * have been deprecated.
 */
open class ECDHClientKeyExchange : ClientKeyExchange {
  companion object {
    private const val LENGTH_BITS = 8 // opaque point <1..2^8-1>

    /**
     * Read encoded point from reader.
     * @param reader reader
     * @return encoded point
     */
    fun readEncodedPoint(reader: DatagramReader): ByteArray = reader.readVarBytes(LENGTH_BITS)

    fun fromReader(reader: DatagramReader): ECDHClientKeyExchange {
      val pointEncoded = readEncodedPoint(reader)
      return ECDHClientKeyExchange(pointEncoded)
    }
  }

  /**
   * Ephemeral public key of client as encoded point.
   */
  val encodedPoint: ByteArray
    get() = field.copyOf(field.size)

  /**
   * Create a [ClientKeyExchange] message.
   * @param encodedPoint the client's ephemeral public key (as encoded point).
   */
  constructor(encodedPoint: ByteArray?) : super() {
    requireNotNull(encodedPoint) { "encoded point cannot be null" }
    this.encodedPoint = encodedPoint
  }

  override fun fragmentToByteArray(): ByteArray {
    val writer = DatagramWriter()
    writeFragment(writer)
    return writer.toByteArray()
  }

  /**
   * Write fragment to writer. Write the encoded point.
   * @param writer writer
   */
  open fun writeFragment(writer: DatagramWriter) {
    writer.writeVarBytes(encodedPoint, LENGTH_BITS)
  }

  override val messageLength: Int
    get() = 1 + encodedPoint.size

  override fun toString(indent: Int): String {
    return StringBuilder(super.toString(indent)).apply sb@{
      val indentation = Utility.indentation(indent + 1)
      this@sb.append(indentation).append("Diffie-Hellman public value: ")
      this@sb.append(Utility.byteArray2HexString(encodedPoint, Utility.NO_SEPARATOR, 16))
      this@sb.append(Utility.LINE_SEPARATOR)
    }.toString()
  }
}
