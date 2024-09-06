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

import io.kaxis.dtls.HandshakeType
import io.kaxis.util.Utility

/**
 * This class represents a fragmented handshake message. It treats the underlying handshake body as
 * transparent data and just helps keeping track of the _fragment_offset_ and _fragment_length_.
 */
class FragmentedHandshakeMessage : HandshakeMessage {
  /**
   * The fragmented handshake body.
   */
  val fragmentedBytes: ByteArray

  /**
   * The handshake message's type.
   */
  override val messageType: HandshakeType

  /**
   * The handshake message's un-fragmented length.
   */
  override val messageLength: Int

  /**
   * The number of bytes contained in previous fragments.
   */
  override val fragmentOffset: Int

  override val fragmentLength: Int
    get() = fragmentedBytes.size

  /**
   * Called when reassembling a handshake message or received a fragment during the handshake.
   * @param type the message's type.
   * @param messageLength the message's total length.
   * @param messageSeq the message's `message_seq`.
   * @param fragmentOffset the message's `fragment_offset`.
   * @param fragmentBytes the fragment's byte representation.
   */
  constructor(type: HandshakeType, messageLength: Int, messageSeq: Int, fragmentOffset: Int, fragmentBytes: ByteArray) {
    this.messageType = type
    this.messageLength = messageLength
    this.fragmentedBytes = fragmentBytes.copyOf(fragmentBytes.size)
    this.fragmentOffset = fragmentOffset
    this.messageSeq = messageSeq
  }

  override val implementationTypePrefix: String
    get() = "Fragmented "

  override fun toString(indent: Int): String {
    return StringBuilder(super.toString(indent)).apply sb@{
      val indentation = Utility.indentation(indent)
      this@sb.append(indentation).append("Fragment Offset: ").append(fragmentOffset).append(Utility.LINE_SEPARATOR)
      this@sb.append(indentation).append("Fragment Length: ").append(fragmentLength).append(" bytes")
        .append(Utility.LINE_SEPARATOR)
    }.toString()
  }

  override fun fragmentToByteArray(): ByteArray {
    return fragmentedBytes
  }
}
