/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.message.handshake

import io.kaxis.dtls.PskPublicInformation
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility

/**
 * The key exchange message sent when using the preshared key exchange algorithm. To help the client in
 * selecting which identity to use, the server can provide a "PSK identity hint" in the _ServerKeyExchange_ message.
 *
 * If no hint is provided, the _ServerKeyExchange_ message is omitted. See [ServerKeyExchange] for the message format.
 */
class PskServerKeyExchange : ServerKeyExchange {
  companion object {
    private const val IDENTITY_HINT_LENGTH_BITS = 16

    fun fromReader(reader: DatagramReader): PskServerKeyExchange {
      val hintEncoded = reader.readVarBytes(IDENTITY_HINT_LENGTH_BITS)
      return PskServerKeyExchange(hintEncoded)
    }
  }

  val hint: PskPublicInformation

  constructor(hint: PskPublicInformation) {
    this.hint = hint
  }

  private constructor(hintEncoded: ByteArray) {
    this.hint = PskPublicInformation.fromByteArray(hintEncoded)
  }

  override val messageLength: Int
    get() {
      // fixed: 2 bytes for the length field
      // http://tools.ietf.org/html/rfc4279#section-2: opaque psk_identity_hint<0..2^16-1>
      return 2 + hint.length()
    }

  override fun toString(indent: Int): String {
    return StringBuilder(super.toString(indent)).apply sb@{
      val indentation = Utility.indentation(indent + 1)
      this@sb.append(indentation).append("PSK Identity Hint: ").append(hint).append(Utility.LINE_SEPARATOR)
    }.toString()
  }

  override fun fragmentToByteArray(): ByteArray {
    val writer = DatagramWriter(hint.length() + 2)
    writer.writeVarBytes(hint, IDENTITY_HINT_LENGTH_BITS)
    return writer.toByteArray()
  }
}
