/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.message.handshake

import io.kaxis.dtls.HandshakeType
import io.kaxis.dtls.message.HandshakeMessage

/**
 * This message is always sent by the client, It **MUST** immediately follow the client certificate message, if it is sent.
 * Otherwise, it **MUST** be the first message sent by the client after it receives the [ServerHelloDone] message. This
 * is a super class for the different key exchange methods (i.e. Diffie-Hellman, RSA, Elliptic Curve Diffie-Hellman).
 * See [RFC 5246](https://tools.ietf.org/html/rfc5246#section-7.4.3).
 */
abstract class ClientKeyExchange : HandshakeMessage() {
  override val messageType: HandshakeType
    get() = HandshakeType.CLIENT_KEY_EXCHANGE
}
