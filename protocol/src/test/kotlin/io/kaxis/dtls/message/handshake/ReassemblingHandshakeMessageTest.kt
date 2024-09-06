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

import io.kaxis.dtls.HandshakeType
import io.kaxis.dtls.message.FragmentedHandshakeMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.util.*

internal class ReassemblingHandshakeMessageTest {
  companion object {
    val LOGGER: Logger = LoggerFactory.getLogger(ReassemblingHandshakeMessageTest::class.java)

    private const val MAX_FRAGMENT_SIZE: Int = 100
    private const val MESSAGE_SIZE: Int = 3000
    private const val MESSAGE_SEQN: Int = 1
    private const val OVERLAPS: Int = 10
  }

  private val rand = Random()

  private lateinit var payload: ByteArray
  private lateinit var fragments: MutableList<FragmentedHandshakeMessage>

  @BeforeEach
  fun setUp() {
    payload = ByteArray(MESSAGE_SIZE)
    rand.nextBytes(payload)
    fragments = arrayListOf()
    var fragmentOffset = 0
    while (fragmentOffset < payload.size) {
      val fragmentLength = MAX_FRAGMENT_SIZE.coerceAtMost(payload.size - fragmentOffset)
      val fragment = ByteArray(fragmentLength)
      System.arraycopy(payload, fragmentOffset, fragment, 0, fragmentLength)
      val msg =
        FragmentedHandshakeMessage(HandshakeType.CERTIFICATE, MESSAGE_SIZE, MESSAGE_SEQN, fragmentOffset, fragment)
      fragments.add(msg)
      fragmentOffset += fragmentLength
    }
  }

  private fun unorder() {
    for (index in 0..<fragments.size) {
      val newIndex = rand.nextInt(fragments.size)
      val message = fragments.removeAt(index)
      fragments.add(newIndex, message)
    }
  }

  private fun overlap(
    quoteBefore: Int,
    quoteAfter: Int,
  ) {
    for (i in 0..<OVERLAPS) {
      val index = rand.nextInt(fragments.size - 2) + 1
      var message = if (quoteAfter > 0) fragments.removeAt(index) else fragments[index]
      var offset = message.fragmentOffset - (message.fragmentLength * quoteBefore) / 100
      var length = message.fragmentLength * (100 + quoteAfter) / 100
      if (offset < 0) {
        offset = 0
      } else if (offset >= MESSAGE_SIZE) {
        offset = MESSAGE_SIZE - 2
      }
      if (length <= 0) {
        length = 1
      } else if (offset + length >= MESSAGE_SIZE) {
        length = MESSAGE_SIZE - offset - 1
      }
      val fragment = ByteArray(length)
      System.arraycopy(payload, offset, fragment, 0, length)
      message = FragmentedHandshakeMessage(HandshakeType.CERTIFICATE, MESSAGE_SIZE, MESSAGE_SEQN, offset, fragment)
      fragments.add(index, message)
    }
  }

  private fun log(msg: FragmentedHandshakeMessage) {
    LOGGER.info(" fragment [{}:{}]", msg.fragmentOffset, msg.fragmentOffset + msg.fragmentLength)
  }

  private fun log() {
    fragments.forEach { log(it) }
  }

  @Test
  fun testReassembleFragmentedHandshakeMessages() {
    var complete = false
    val message = ReassemblingHandshakeMessage(fragments[0])
    fragments.forEach { msg ->
      assertFalse(complete, "message completed with left fragments")
      message.add(msg)
      complete = message.isComplete
      LOGGER.info("{}", message)
    }

    assertTrue(complete, "message incomplete")
    assertArrayEquals(payload, message.fragmentToByteArray())
  }

  @Test
  fun testReassembleFragmentedHandshakeMessagesUnordered() {
    unorder()
    var complete = false
    val message = ReassemblingHandshakeMessage(fragments[0])
    fragments.forEach { msg ->
      assertFalse(complete, "message completed with left fragments")
      message.add(msg)
      complete = message.isComplete
      LOGGER.info("{}", message)
    }

    assertTrue(complete, "message incomplete")
    assertArrayEquals(payload, message.fragmentToByteArray())
  }

  @Test
  fun testReassembleFragmentedHandshakeMessagesOverlapping() {
    overlap(100, 100)
    overlap(50, 50)
    overlap(50, -50)
    var complete = false
    val message = ReassemblingHandshakeMessage(fragments[0])
    fragments.forEach { msg ->
      assertFalse(complete, "message completed with left fragments")
      message.add(msg)
      complete = message.isComplete
      LOGGER.info("{}", message)
    }

    assertTrue(complete, "message incomplete")
    assertArrayEquals(payload, message.fragmentToByteArray())
  }

  @Test
  fun testReassembleFragmentedHandshakeMessagesOverlappingUnordered() {
    overlap(50, 50)
    overlap(100, 100)
    overlap(50, -50)
    unorder()
    log()
    var complete = false
    val message = ReassemblingHandshakeMessage(fragments[0])
    fragments.forEach { msg ->
      message.add(msg)
      complete = message.isComplete || complete
      LOGGER.info("{}", message)
    }

    assertTrue(complete, "message incomplete")
    assertArrayEquals(payload, message.fragmentToByteArray())
  }

  @Test
  fun testReassembleIncompleteFragmentedHandshakeMessages() {
    val index = rand.nextInt(fragments.size)
    fragments.removeAt(index)
    var complete = false
    val message = ReassemblingHandshakeMessage(fragments[0])
    fragments.forEach { msg ->
      assertFalse(complete, "message completed with left fragments")
      message.add(msg)
      complete = message.isComplete
      LOGGER.info("{}", message)
    }

    assertFalse(complete, "message completed with incomplete fragments")
  }

  @Test
  fun testAddFragmentedHandshakeMessageAfterComplete() {
    var complete = false
    val first = fragments[0]
    val additionalMsg =
      FragmentedHandshakeMessage(
        HandshakeType.CERTIFICATE,
        MESSAGE_SIZE,
        MESSAGE_SEQN,
        first.fragmentLength,
        first.fragmentedBytes,
      )
    fragments.add(additionalMsg)
    val message = ReassemblingHandshakeMessage(first)
    fragments.forEach { msg ->
      message.add(msg)
      complete = message.isComplete
      LOGGER.info("{}", message)
    }

    assertTrue(complete, "message incomplete")
    assertArrayEquals(payload, message.fragmentToByteArray())
  }

  @Test
  fun testDifferentMessageType() {
    val first = fragments[0]
    val message = ReassemblingHandshakeMessage(first)
    val msg =
      FragmentedHandshakeMessage(
        HandshakeType.SERVER_KEY_EXCHANGE,
        MESSAGE_SIZE,
        MESSAGE_SEQN,
        first.fragmentLength,
        first.fragmentedBytes,
      )
    assertThrows<IllegalArgumentException> {
      message.add(msg)
    }
  }

  @Test
  fun testDifferentMessageSize() {
    val first = fragments[0]
    val message = ReassemblingHandshakeMessage(first)
    val msg =
      FragmentedHandshakeMessage(
        HandshakeType.CERTIFICATE,
        MESSAGE_SIZE - 1,
        MESSAGE_SEQN,
        first.fragmentLength,
        first.fragmentedBytes,
      )
    assertThrows<IllegalArgumentException> {
      message.add(msg)
    }
  }

  @Test
  fun testDifferentMessageSeqn() {
    val first = fragments[0]
    val message = ReassemblingHandshakeMessage(first)
    val msg =
      FragmentedHandshakeMessage(
        HandshakeType.CERTIFICATE,
        MESSAGE_SIZE,
        MESSAGE_SEQN + 1,
        first.fragmentLength,
        first.fragmentedBytes,
      )
    assertThrows<IllegalArgumentException> {
      message.add(msg)
    }
  }

  @Test
  fun testFragmentExceedMessageSize() {
    val first = fragments[0]
    val message = ReassemblingHandshakeMessage(first)
    val msg =
      FragmentedHandshakeMessage(
        HandshakeType.CERTIFICATE,
        MESSAGE_SIZE,
        MESSAGE_SEQN,
        first.fragmentLength,
        payload,
      )
    assertThrows<IllegalArgumentException> {
      message.add(msg)
    }
  }
}
