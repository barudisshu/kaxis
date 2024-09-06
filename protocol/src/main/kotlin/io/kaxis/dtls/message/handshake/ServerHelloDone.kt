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
 * The ServerHelloDone message is sent by the server to indicate the end of the [ServerHello] and associated
 * messages. After sending this message, the server will wait for a client response. See [RFC 5246](https://tools.ietf.org/html/rfc5246#section-7.4.5) for details.
 */
class ServerHelloDone : HandshakeMessage() {
  override val messageType: HandshakeType
    get() = HandshakeType.SERVER_HELLO_DONE

  override val messageLength: Int
    get() = 0

  override fun fragmentToByteArray(): ByteArray {
    return Bytes.EMPTY_BYTES
  }
}
