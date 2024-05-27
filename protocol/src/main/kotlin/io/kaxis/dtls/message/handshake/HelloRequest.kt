/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.message.handshake

import io.kaxis.Bytes
import io.kaxis.dtls.HandshakeType
import io.kaxis.dtls.message.HandshakeMessage

/**
 * _HelloRequest_ i a simple notification that the client should begin the negotiation process anew. In response,
 * the client should send a [ClientHello] message when convenient. This message is not intended to establish
 * which side is the client or server but merely to initiate a new negotiation. See [RFC 5246](https://tools.ietf.org/html/rfc5246#section-7.4.1.1) for details.
 */
class HelloRequest : HandshakeMessage() {
  override val messageType: HandshakeType
    get() = HandshakeType.HELLO_REQUEST

  override val messageLength: Int
    get() = 0

  override fun fragmentToByteArray(): ByteArray {
    return Bytes.EMPTY_BYTES
  }
}
