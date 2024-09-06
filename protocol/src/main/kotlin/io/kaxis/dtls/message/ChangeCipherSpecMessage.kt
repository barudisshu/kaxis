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
import io.kaxis.exception.HandshakeException
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility

/**
 * The change cipher spec protocol exists to signal transitions in ciphering strategies. The protocol consists of a
 * single message, which is encrypted and compressed under the current (not the pending) connection state.
 *
 * The `ChangeCipherSpec` message is sent by both the client and the server to notify the receiving party that
 * later records will be protected under the newly negotiated CipherSpec and keys. For further details see
 * [RFC 5246](https://tools.ietf.org/html/rfc5246#section-7.1).
 */
class ChangeCipherSpecMessage : DTLSMessage {
  companion object {
    private const val CCS_BITS: Int = 8

    @JvmStatic
    @Throws(HandshakeException::class)
    fun fromByteArray(byteArray: ByteArray?): ChangeCipherSpecMessage {
      val reader = DatagramReader(byteArray)
      val code = reader.read(CCS_BITS)
      if (code == CCSType.CHANGE_CIPHER_SPEC.code) {
        if (reader.bytesAvailable()) {
          throw HandshakeException(
            AlertMessage(
              AlertMessage.AlertLevel.FATAL,
              AlertMessage.AlertDescription.DECODE_ERROR,
            ),
            "Change Cipher Spec must be empty!",
          )
        }
        return ChangeCipherSpecMessage()
      } else {
        throw HandshakeException(
          AlertMessage(
            AlertMessage.AlertLevel.FATAL,
            AlertMessage.AlertDescription.ILLEGAL_PARAMETER,
          ),
          "Unknown Change Cipher Spec code received: $code",
        )
      }
    }
  }

  @Suppress("ktlint:standard:property-naming")
  val CCSProtocolType: CCSType = CCSType.CHANGE_CIPHER_SPEC

  /**
   * See [RFC 5246](https://tools.ietf.org/html/rfc5246#section-7.1) for specification.
   */
  enum class CCSType(val code: Int) {
    CHANGE_CIPHER_SPEC(1),
  }

  override val size: Int
    get() = CCS_BITS / Byte.SIZE_BITS

  override fun toByteArray(): ByteArray? {
    val writer = DatagramWriter(1)
    writer.write(CCSProtocolType.code, CCS_BITS)
    return writer.toByteArray()
  }

  override val contentType: ContentType
    get() = ContentType.CHANGE_CIPHER_SPEC

  override fun toString(indent: Int): String {
    return "${Utility.indentation(indent)}Change Cipher Spec Message${Utility.LINE_SEPARATOR}"
  }

  override fun toString(): String {
    return toString(0)
  }
}
