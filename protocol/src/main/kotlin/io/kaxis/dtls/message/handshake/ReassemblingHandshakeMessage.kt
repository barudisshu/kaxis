/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.message.handshake

import io.kaxis.dtls.message.FragmentedHandshakeMessage
import io.kaxis.util.NoPublicAPI
import io.kaxis.util.Utility

/**
 * Reassemble fragmented handshake messages.
 *
 * According [RFC 6347, Section 4.2.3](https://datatracker.ietf.org/doc/rfc6347#section-4.2.3) "DTLS implementations
 * MUST be able to handle overlapping fragment ranges". Therefore, the processing of overlapping fragments is
 * optimized by early testing if it contains a new data-range and merging of adjacent ranges afterward.
 */
@NoPublicAPI
class ReassemblingHandshakeMessage : GenericHandshakeMessage {
  /**
   * The reassembled fragments handshake body.
   */
  val reassembledBytes: ByteArray

  /**
   * The list of fragment ranges.
   */
  val fragments: MutableList<FragmentRange> = arrayListOf()

  class FragmentRange(var offset: Int, var length: Int) {
    var end: Int

    init {
      this.end = offset + length
    }

    /**
     * Reduce end.
     *
     * @param end new lower end. Same of higher end is ignored
     * @throws IllegalArgumentException if new end is before offset.
     */
    fun reduceEnd(end: Int) {
      if (this.end > end) {
        require(end >= this.offset) { "adjusted end before offset!" }
        this.end = end
        this.length = this.end - this.offset
      }
    }

    /**
     * Amend end.
     *
     * @param end new higher end. Same or lower end is ignored.
     */
    fun amendEnd(end: Int) {
      if (this.end < end) {
        this.end = end
        this.length = this.end - this.offset
      }
    }

    /**
     * Skip offset.
     *
     * @param offset new higher offset. Same or lower offset is ignored.
     * @return number of skipped bytes
     */
    fun skipToOffset(offset: Int): Int {
      var skip = 0
      if (this.offset < offset) {
        if (this.end <= offset) {
          // new offset after end => empty range
          this.length = 0
          this.offset = offset
          this.end = offset
        } else {
          skip = offset - this.offset
          this.offset = offset
          this.length = this.end - this.offset
        }
      }

      return skip
    }

    override fun toString(): String {
      return String.format("range[%d:%d)", offset, end)
    }
  }

  /**
   * Called when reassembling a handshake message or received a fragment during the handshake.
   * @param message starting fragmented message.
   */
  constructor(message: FragmentedHandshakeMessage) : super(message.messageType) {
    messageSeq = message.messageSeq
    reassembledBytes = ByteArray(message.messageLength)
    add(0, 0, FragmentRange(message.fragmentOffset, message.fragmentLength), message)
  }

  /**
   * Check, if message reassembling is complete.
   * @return `true`, if message is complete
   */
  val isComplete: Boolean
    get() {
      // check, if first range is from 0 to message length
      val firstRange = fragments[0]
      return firstRange.offset == 0 && messageLength <= firstRange.end
    }

  /**
   * Add data of fragment to reassembled data. Optimize processing of overlapping fragments by early
   * testing, if it contains a new data-range and merging of adjacent ranges before returning.
   *
   * @param message fragmented handshake message
   * @throws IllegalArgumentException if type, sequence number, or total message length, doesn't
   * match the previous fragments. Or the fragment exceeds the handshake message.
   */
  fun add(message: FragmentedHandshakeMessage) {
    require(messageType == message.messageType) {
      "Fragment message type ${message.messageType} differs from $messageType!"
    }
    require(messageSeq == message.messageSeq) {
      "Fragment message sequence number ${message.messageSeq} differs from $messageSeq!"
    }
    require(messageLength == message.messageLength) {
      "Fragment message length ${message.messageLength} differs from $messageLength!"
    }
    if (isComplete) {
      return
    }

    val newRange = FragmentRange(message.fragmentOffset, message.fragmentLength)
    require(messageLength >= newRange.end) {
      "Fragment message ${newRange.end} bytes exceeds message $messageLength bytes!"
    }

    var end = 0
    var position = 0
    while (position < fragments.size) {
      val currentRange = fragments[position]
      when {
        newRange.offset < currentRange.offset -> {
          if (currentRange.offset < newRange.end && newRange.end <= currentRange.end) {
            // overlap [new [cur new) cur)
            // reduce range to [new cur)
            newRange.reduceEnd(currentRange.offset)
          }
          break
        }
        newRange.end <= currentRange.end -> {
          // overlap [cur [new  new) cur) or
          // overlap [cur=new new) cur)
          // already reassembled
          return
        }
        newRange.offset == currentRange.offset -> {
          // overlap [cur=new cur) new)
          // add after current range
          ++position
          break
        }
      }

      position++
      end = currentRange.end
    }

    // check for overlap [cur [new cur) new)
    // skip offset to [cur.end new)
    val skip = newRange.skipToOffset(end)
    if (newRange.length == 0) {
      // no bytes left, fragments data already reassembled
      return
    }
    // add new data
    add(position, skip, newRange, message)
    var currentRange = fragments[0]
    // try to merge adjacent ranges
    position = 1
    while (position < fragments.size) {
      val nextRange = fragments[position]
      if (nextRange.offset <= currentRange.end) {
        // check for overlap [cur [new cur) new)
        // merge range to [cur new)
        currentRange.amendEnd(nextRange.end)
        fragments.removeAt(position)
        --position
      } else {
        currentRange = nextRange
      }
      position++
    }
  }

  /**
   * Add range and position and copy fragment.
   *
   * @param position position to add range
   * @param skip number of skipped bytes from message
   * @param range range to add
   * @param message fragment to copy
   * @see fragments
   * @see reassembledBytes
   */
  private fun add(
    position: Int,
    skip: Int,
    range: FragmentRange,
    message: FragmentedHandshakeMessage,
  ) {
    fragments.add(position, range)
    System.arraycopy(message.fragmentToByteArray(), skip, reassembledBytes, range.offset, range.length)
  }

  override val messageLength: Int
    get() = reassembledBytes.size

  override val implementationTypePrefix: String
    get() = "Reassembling "

  override fun fragmentToByteArray(): ByteArray {
    return reassembledBytes
  }

  override fun toString(indent: Int): String {
    val sb = StringBuilder(super.toString(indent))
    val indentation = Utility.indentation(indent)
    val indentation2 = Utility.indentation(indent + 1)
    sb.append(indentation).append("Reassembled Fragments: ").append(fragments.size).append(Utility.LINE_SEPARATOR)
    fragments.forEach { range ->
      sb.append(indentation2).append(range).append(Utility.LINE_SEPARATOR)
    }
    return sb.toString()
  }
}
