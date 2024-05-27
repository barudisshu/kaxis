/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.message.handshake

import io.kaxis.dtls.HandshakeType
import io.kaxis.dtls.message.HandshakeMessage

/**
 * This message will be sent immediately after the server [CertificateMessage] (or the [ServerHello] message, if
 * this is an anonymous negotiation). See [RFC 5246](https://tools.ietf.org/html/rfc5246#section-7.4.3) for details.
 */
abstract class ServerKeyExchange : HandshakeMessage() {
  override val messageType: HandshakeType
    get() = HandshakeType.SERVER_KEY_EXCHANGE
}
