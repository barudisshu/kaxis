/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.message.handshake

import io.kaxis.dtls.HandshakeType
import io.kaxis.dtls.message.HandshakeMessage
import io.kaxis.util.NoPublicAPI

/**
 * Generic handshake message. Use to partially process handshake messages, if they are received out of order an
 * the full processing requires the [HandshakeParameter]. Offsets later creation of specific handshake messages, if
 * the handshake parameters are available.
 */
@NoPublicAPI
open class GenericHandshakeMessage(override val messageType: HandshakeType) : HandshakeMessage() {
  companion object {
    fun fromByteArray(type: HandshakeType): GenericHandshakeMessage = GenericHandshakeMessage(type)
  }

  override val messageLength: Int
    get() {
      val rm = rawMessage
      return if (rm != null) {
        rm.size - MESSAGE_HEADER_LENGTH_BYTES
      } else {
        0
      }
    }

  override fun fragmentToByteArray(): ByteArray? {
    val rawMessage = rawMessage
    return rawMessage?.copyOfRange(MESSAGE_HEADER_LENGTH_BYTES, rawMessage.size)
  }

  override val implementationTypePrefix: String
    get() = "Generic "
}
