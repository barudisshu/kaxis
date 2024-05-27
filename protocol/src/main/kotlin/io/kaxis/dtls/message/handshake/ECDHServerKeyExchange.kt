/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.message.handshake

import io.kaxis.dtls.cipher.XECDHECryptography
import io.kaxis.dtls.message.AlertMessage
import io.kaxis.exception.HandshakeException
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility
import java.security.Signature
import java.security.SignatureException

/**
 * The server's ephemeral ECDH.
 *
 * See [RFC 4492, section 5.4 Server Key Exchange](https://tools.ietf.org/html/rfc4492#section-5.4) for details regarding the message format.
 *
 * According [RFC 8422, 5.1.1. Supported Elliptic Curves Extension](https://tools.ietf.org/html/rfc8422#section-5.1.1) only
 * "named curves" are valid, the "rime" and "char2" curve descriptions are deprecated. Also only "UNCOMPRESSED" as point format
 * is valid, the other formats have been deprecated.
 */
abstract class ECDHServerKeyExchange : ServerKeyExchange {
  companion object {
    private const val CURVE_TYPE_BITS = 8
    private const val NAMED_CURVE_BITS = 16
    private const val PUBLIC_LENGTH_BITS = 8

    // a named curve is used.

    /**
     * The ECCurveType
     */
    private const val NAMED_CURVE = 3

    @Throws(HandshakeException::class)
    fun readNamedCurve(reader: DatagramReader): EcdhData {
      val curveType = reader.read(CURVE_TYPE_BITS)
      if (curveType != NAMED_CURVE) {
        throw HandshakeException(
          AlertMessage(
            AlertMessage.AlertLevel.FATAL,
            AlertMessage.AlertDescription.HANDSHAKE_FAILURE,
          ),
          "Curve type [%s] received in ServerKeyExchange message is unsupported".format(curveType),
        )
      }
      val curveId = reader.read(NAMED_CURVE_BITS)
      val group = XECDHECryptography.SupportedGroup.fromId(curveId)
      if (group == null || !group.isUsable) {
        throw HandshakeException(
          AlertMessage(
            AlertMessage.AlertLevel.FATAL,
            AlertMessage.AlertDescription.ILLEGAL_PARAMETER,
          ),
          "Server used unsupported elliptic curve (%d) for ECDH".format(curveId),
        )
      }
      val encodedPoint = reader.readVarBytes(PUBLIC_LENGTH_BITS)
      return EcdhData(group, encodedPoint)
    }
  }

  val supportedGroup: XECDHECryptography.SupportedGroup

  val encodedPoint: ByteArray
    get() = field.copyOf(field.size)

  /**
   * Called when reconstructing the byte array.
   * @param supportedGroup supported group (named curve)
   * @param encodedPoint the encoded point on the curve (public key).
   * @throws NullPointerException if one of the parameters are `null`
   */
  constructor(supportedGroup: XECDHECryptography.SupportedGroup?, encodedPoint: ByteArray?) {
    requireNotNull(supportedGroup) { "Supported group (curve) must not be null!" }
    requireNotNull(encodedPoint) { "encoded point must not be null!" }
    this.supportedGroup = supportedGroup
    this.encodedPoint = encodedPoint
  }

  val namedCurveLength: Int
    get() = 4 + encodedPoint.size

  fun writeNamedCurve(writer: DatagramWriter) {
    // http://tools.ietf.org/html/rfc4492#section-5.4
    writer.write(NAMED_CURVE, CURVE_TYPE_BITS)
    writer.write(supportedGroup.id, NAMED_CURVE_BITS)
    writer.writeVarBytes(encodedPoint, PUBLIC_LENGTH_BITS)
  }

  @Throws(SignatureException::class)
  fun updateSignatureForNamedCurve(signature: Signature) {
    val curveId = supportedGroup.id
    signature.update(NAMED_CURVE.toByte())
    signature.update((curveId shr 8).toByte())
    signature.update(curveId.toByte())
    signature.update(encodedPoint.size.toByte())
    signature.update(encodedPoint)
  }

  override fun toString(indent: Int): String {
    return StringBuilder(super.toString(indent)).apply sb@{
      val indentation = Utility.indentation(indent + 1)
      this@sb.append(indentation).append("Diffie-Hellman public key: ")
      this@sb.append(supportedGroup.name).append("-")
        .append(Utility.byteArray2HexString(encodedPoint, Utility.NO_SEPARATOR, 16))
      this@sb.append(Utility.LINE_SEPARATOR)
    }.toString()
  }

  /**
   * Utility class to keep results of reading the supported group and the encoded point.
   */
  class EcdhData(val supportedGroup: XECDHECryptography.SupportedGroup, val encodedPoint: ByteArray)
}
