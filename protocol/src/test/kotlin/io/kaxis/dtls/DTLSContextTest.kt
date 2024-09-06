/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls

import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.SecretIvParameterSpec
import io.kaxis.util.SecretUtil
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

internal class DTLSContextTest {
  companion object {
    private val RANDOM = java.util.Random()

    fun newEstablishedServerDtlsContext(
      cipherSuite: CipherSuite,
      type: CertificateType,
    ): DTLSContext {
      var macKey: SecretKey? = null
      if (cipherSuite.macKeyLength > 0) {
        macKey = SecretKeySpec(getRandomBytes(cipherSuite.macKeyLength), "AES")
      }
      val encryptionKey = SecretKeySpec(getRandomBytes(cipherSuite.encKeyLength), "AES")
      val iv = SecretIvParameterSpec(getRandomBytes(cipherSuite.fixedIvLength))

      val session = DTLSSessionTest.newEstablishedServerSession(cipherSuite, type)
      val context = DTLSContext(0, false)
      context.session.set(session)
      SecretUtil.destroy(session)
      context.createReadState(encryptionKey, iv, macKey)
      context.createWriteState(encryptionKey, iv, macKey)
      return context
    }

    fun reload(context: DTLSContext): DTLSContext? {
      val writer = DatagramWriter()
      if (context.writeTo(writer)) {
        val reader = DatagramReader(writer.toByteArray())
        return DTLSContext.fromReader(reader)
      }
      return null
    }

    fun getRandomBytes(length: Int): ByteArray {
      val result = ByteArray(length)
      RANDOM.nextBytes(result)
      return result
    }
  }

  lateinit var context: DTLSContext

  @BeforeEach
  fun setUp() {
    context = newEstablishedServerDtlsContext(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CertificateType.X_509)
  }

  @Test
  fun testRecordFromPreviousEpochIsDiscarded() {
    context.readEpoch = 1
    assertThrows<IllegalArgumentException> { context.isRecordProcessable(0, 15, 0) }
  }

  @Test
  fun testRecordFromFutureEpochIsDiscarded() {
    context.readEpoch = 1
    assertThrows<IllegalArgumentException> { context.isRecordProcessable(2, 15, 0) }
  }

  @Test
  fun testRecordShiftsReceiveWindow() {
    val epoch = 0
    context.readEpoch = epoch
    // session.markRecordAsRead(epoch, 0)
    context.markRecordAsRead(epoch, 2)
    assertTrue(context.isRecordProcessable(0, 0, 0))
    assertTrue(context.isRecordProcessable(0, 1, 0))
    assertFalse(context.isRecordProcessable(0, 2, 0))
    assertTrue(context.isRecordProcessable(0, 64, 0))

    // make a right shift by 1 position
    context.markRecordAsRead(epoch, 64)
    assertFalse(context.isRecordProcessable(0, 0, 0))
    assertTrue(context.isRecordProcessable(0, 1, 0))
    assertFalse(context.isRecordProcessable(0, 2, 0))
    assertFalse(context.isRecordProcessable(0, 64, 0))

    val context2 = reload(context)
    assertEquals(context, context2)
  }

  @Test
  fun testRecordShiftsReceiveWindowUsingWindowFilter() {
    val epoch = 0
    context.readEpoch = epoch
    // session.markRecordAsRead(epoch, 0)
    context.markRecordAsRead(epoch, 2)
    assertTrue(context.isRecordProcessable(0, 0, -1))
    assertTrue(context.isRecordProcessable(0, 1, -1))
    assertFalse(context.isRecordProcessable(0, 2, -1))
    assertTrue(context.isRecordProcessable(0, 64, -1))
    assertTrue(context.isRecordProcessable(0, 100, -1))

    // make a right shift by 1 position
    context.markRecordAsRead(epoch, 64)
    assertTrue(context.isRecordProcessable(0, 0, -1))
    assertTrue(context.isRecordProcessable(0, 1, -1))
    assertFalse(context.isRecordProcessable(0, 2, -1))
    assertFalse(context.isRecordProcessable(0, 64, -1))
    assertTrue(context.isRecordProcessable(0, 100, -1))

    val context2 = reload(context)
    assertEquals(context, context2)
  }

  @Test
  fun testRecordShiftsReceiveWindowUsingExtendedWindowFilter() {
    val epoch = 0
    context.readEpoch = epoch
    // session.markRecordAsRead(epoch, 0)
    context.markRecordAsRead(epoch, 2)
    assertTrue(context.isRecordProcessable(0, 0, 8))
    assertTrue(context.isRecordProcessable(0, 1, 8))
    assertFalse(context.isRecordProcessable(0, 2, 8))
    assertTrue(context.isRecordProcessable(0, 64, 8))
    assertTrue(context.isRecordProcessable(0, 100, 8))

    // make a right shift by 1 position
    context.markRecordAsRead(epoch, 80)
    assertFalse(context.isRecordProcessable(0, 0, 8))
    assertFalse(context.isRecordProcessable(0, 1, 8))
    assertFalse(context.isRecordProcessable(0, 2, 8))
    assertFalse(context.isRecordProcessable(0, 12, 0))
    assertTrue(context.isRecordProcessable(0, 12, 8))
    assertFalse(context.isRecordProcessable(0, 80, 8))
    assertTrue(context.isRecordProcessable(0, 100, 8))

    val context2 = reload(context)
    assertEquals(context, context2)
  }

  @Test
  fun testEpochSwitchResetsReceiveWindow() {
    val epoch = context.readEpoch
    context.markRecordAsRead(epoch, 0)
    context.markRecordAsRead(epoch, 2)
    assertFalse(context.isRecordProcessable(context.readEpoch, 0, 0))
    assertFalse(context.isRecordProcessable(context.readEpoch, 2, 0))

    context.incrementReadEpoch()
    assertTrue(context.isRecordProcessable(context.readEpoch, 0, 0))
    assertTrue(context.isRecordProcessable(context.readEpoch, 2, 0))

    val context2 = reload(context)
    assertEquals(context, context2)
  }

  @Test
  fun testHigherSequenceNumberIsNewer() {
    val epoch = context.readEpoch
    context.markRecordAsRead(epoch, 0)
    assertTrue(context.markRecordAsRead(epoch, 2))
  }

  @Test
  fun testLowerSequenceNumberIsNotNewer() {
    val epoch = context.readEpoch
    context.markRecordAsRead(epoch, 2)
    assertFalse(context.markRecordAsRead(epoch, 0))
  }

  @Test
  fun testSameSequenceNumberIsNotNewer() {
    val epoch = context.readEpoch
    context.markRecordAsRead(epoch, 2)
    assertFalse(context.markRecordAsRead(epoch, 2))
  }

  @Test
  fun testHigherEpochFails() {
    val epoch = context.readEpoch
    context.markRecordAsRead(epoch, 2)
    assertThrows<IllegalArgumentException> { context.markRecordAsRead(epoch + 1, 0) }
  }

  @Test
  fun testLowerEpochFails() {
    val epoch = context.readEpoch
    context.markRecordAsRead(epoch, 0)
    assertThrows<IllegalArgumentException> { context.markRecordAsRead(epoch - 1, 2) }
  }

  @Test
  fun testConstructorEnforcesMaxSequenceNo() {
    context = DTLSContext(Record.MAX_SEQUENCE_NO, false) // intended to succeed
    try {
      context = DTLSContext(Record.MAX_SEQUENCE_NO + 1, false) // intended to fail
      fail("DTLSSession constructor should have refused initial sequence number > 2^48 - 1")
    } catch (e: IllegalArgumentException) {
      // ok
    }
  }

  @Test
  fun testGetSequenceNumberEnforcesMaxSequenceNo() {
    context = DTLSContext(Record.MAX_SEQUENCE_NO, false)
    context.getNextSequenceNumber() // should succeed
    assertThrows<IllegalStateException> { context.getNextSequenceNumber() } // should throw exception
  }
}
