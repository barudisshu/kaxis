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

import io.kaxis.dtls.PskPublicInformation
import io.kaxis.dtls.cipher.XECDHECryptography
import io.kaxis.exception.HandshakeException
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility

class EcdhPskServerKeyExchange : ECDHServerKeyExchange {
  companion object {
    private const val IDENTITY_HINT_LENGTH_BITS = 16

    /**
     * Creates a new server key exchange instance from its byte representation.
     * @param reader reader for the binary encoding of the message.
     * @return [EcdhPskServerKeyExchange]
     * @throws HandshakeException if the byte array includes unsupported curve
     * @throws NullPointerException if either byte array or peer address is `null`
     */
    @Throws(HandshakeException::class)
    fun fromReader(reader: DatagramReader): EcdhPskServerKeyExchange {
      val hintEncoded = reader.readVarBytes(IDENTITY_HINT_LENGTH_BITS)
      val ecdhData = readNamedCurve(reader)
      return EcdhPskServerKeyExchange(hintEncoded, ecdhData.supportedGroup, ecdhData.encodedPoint)
    }
  }

  /**
   * The hint in cleartext.
   */
  val hint: PskPublicInformation

  /**
   * Creates a new key exchange message with psk hint as clear text and ServerDHParams.
   * @param pskHint preshared key hint in clear text
   * @param ecdhe XECDHECryptography including the supported group and the peer's public key
   * @throws NullPointerException if the arguments pskHint or ecdhe are `null`
   */
  constructor(pskHint: PskPublicInformation?, ecdhe: XECDHECryptography?) : super(
    ecdhe?.supportedGroup,
    ecdhe?.encodedPoint,
  ) {
    requireNotNull(pskHint) { "PSK hint must not be null" }
    this.hint = pskHint
  }

  @Throws(HandshakeException::class)
  private constructor(
    hintEncoded: ByteArray,
    supportedGroup: XECDHECryptography.SupportedGroup,
    encodedPoint: ByteArray,
  ) : super(supportedGroup, encodedPoint) {
    this.hint = PskPublicInformation.fromByteArray(hintEncoded)
  }

  override fun fragmentToByteArray(): ByteArray {
    val writer = DatagramWriter()
    writer.writeVarBytes(hint, IDENTITY_HINT_LENGTH_BITS)
    writeNamedCurve(writer)
    return writer.toByteArray()
  }

  override val messageLength: Int
    get() = 2 + hint.length() + namedCurveLength

  override fun toString(indent: Int): String {
    val sb = StringBuilder(super.toString(indent))
    val indentation = Utility.indentation(indent + 1)
    sb.append(indentation).append("PSK Identity Hint: ")
    if (hint.isEmpty()) {
      sb.append("not present!")
    } else {
      sb.append(hint)
    }
    sb.append(Utility.LINE_SEPARATOR)
    return sb.toString()
  }
}
