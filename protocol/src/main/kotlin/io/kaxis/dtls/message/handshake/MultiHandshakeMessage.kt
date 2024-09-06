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

import io.kaxis.dtls.DEFAULT_ETH_MTU
import io.kaxis.dtls.HandshakeType
import io.kaxis.dtls.message.HandshakeMessage
import io.kaxis.util.DatagramWriter
import io.kaxis.util.NoPublicAPI

/**
 * Multi handshake messages.
 *
 * Accumulate multi-handshake messages to be sent as one DTLS record.
 */
@NoPublicAPI
class MultiHandshakeMessage : HandshakeMessage() {
  /**
   * Number of added handshake messages.
   */
  private var count: Int = 0

  /**
   * Length of added handshake messages.
   */
  private var length: Int = 0

  /**
   * Last added handshake message.
   */
  private var tail: HandshakeMessage = this

  /**
   * Get number of added handshake messages.
   */
  val numberOfHandshakeMessages: Int
    /**
     * @return number of added handshake messages.
     */
    get() = count

  fun add(message: HandshakeMessage) {
    tail.nextHandshakeMessage = message
    tail = message
    length += message.size
    count++
  }

  operator fun plusAssign(message: HandshakeMessage) {
    add(message)
  }

  override val messageType: HandshakeType
    get() {
      val message = nextHandshakeMessage
      return message!!.messageType
    }

  override val messageLength: Int
    get() = length - MESSAGE_HEADER_LENGTH_BYTES

  override fun fragmentToByteArray(): ByteArray? {
    throw UnsupportedOperationException("MultiHandshakeMessage cannot be converted to fragments.")
  }

  override fun toByteArray(): ByteArray {
    val writer = DatagramWriter(DEFAULT_ETH_MTU)
    var message = nextHandshakeMessage
    while (message != null) {
      message.writeTo(writer)
      message = message.nextHandshakeMessage
    }
    return writer.toByteArray()
  }

  override val implementationTypePrefix: String
    get() = "Multi "
}
