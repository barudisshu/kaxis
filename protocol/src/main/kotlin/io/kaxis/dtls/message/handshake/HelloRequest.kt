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
