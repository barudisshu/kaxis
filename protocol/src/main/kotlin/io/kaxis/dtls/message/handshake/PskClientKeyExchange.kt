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
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility

/**
 * When using preshared keys for key agreement, the client indicates which key to use by including a "PSK indentity"
 * in this message. The server can protentially provide a "PSK identity hint" to help the client selecting which
 * identity to use. See [RFC 4279](https://tools.ietf.org/html/rfc4279#section-2) for details.
 */
class PskClientKeyExchange : ClientKeyExchange {
  companion object {
    private const val IDENTITY_LENGTH_BITS = 16

    fun fromReader(reader: DatagramReader): PskClientKeyExchange {
      val identityEncoded = reader.readVarBytes(IDENTITY_LENGTH_BITS)
      return PskClientKeyExchange(identityEncoded)
    }
  }

  /**
   * The identity in cleartext.
   */
  val identity: PskPublicInformation

  constructor(identity: PskPublicInformation) {
    this.identity = identity
  }

  private constructor(identityEncoded: ByteArray) {
    this.identity = PskPublicInformation.fromByteArray(identityEncoded)
  }

  override val messageLength: Int
    // fixed: 2 bytes for the length field
    // http://tools.ietf.org/html/rfc4279#section-2: opaque psk_identity<0..2^16-1>
    get() = 2 + identity.length()

  override fun fragmentToByteArray(): ByteArray {
    val writer = DatagramWriter(identity.length() + 2)
    writer.writeVarBytes(identity, IDENTITY_LENGTH_BITS)
    return writer.toByteArray()
  }

  override fun toString(indent: Int): String {
    return StringBuilder(super.toString(indent)).apply sb@{
      val indentation = Utility.indentation(indent + 1)
      this@sb.append(indentation).append("PSK Identity: ").append(identity).append(Utility.LINE_SEPARATOR)
    }.toString()
  }
}
