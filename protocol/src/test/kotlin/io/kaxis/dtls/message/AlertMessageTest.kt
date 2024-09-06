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

import io.kaxis.exception.HandshakeException
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.*

internal class AlertMessageTest {
  companion object {
    private const val UNKNOWN_LEVEL: Byte = 0x20
    private const val UNKNOWN_DESCRIPTION: Byte = 0xFD.toByte()
  }

  @Test
  @Throws(HandshakeException::class)
  fun testFromByteArraySuccessfullyParseLevelAndDescription() {
    // GIVEN a record containing a fatal handshake failure alert message
    val fragment =
      byteArrayOf(
        AlertMessage.AlertLevel.FATAL.code.toByte(),
        AlertMessage.AlertDescription.HANDSHAKE_FAILURE.code.toByte(),
      )

    // WHEN parsing the record
    val alert = AlertMessage.fromByteArray(fragment)

    // THEN the level is FATAL and the description is HANDSHAKE_FAILURE
    assertEquals(AlertMessage.AlertLevel.FATAL, alert.level)
    assertEquals(AlertMessage.AlertDescription.HANDSHAKE_FAILURE, alert.description)
  }

  @Test
  fun testFromByteArrayThrowsExceptionForUnknownLevel() {
    // GIVEN a record containing an alert message with an undefined alert level
    val fragment = byteArrayOf(UNKNOWN_LEVEL, AlertMessage.AlertDescription.HANDSHAKE_FAILURE.code.toByte())

    // WHEN parsing the record
    val thrown =
      assertThrows<HandshakeException> {
        AlertMessage.fromByteArray(fragment)
        fail("Should have thrown ${HandshakeException::class.simpleName}")
      }
    assertEquals(AlertMessage.AlertLevel.FATAL, thrown.alert.level)
  }

  @Test
  fun testFromByteArrayThrowsExceptionForUnknownDescription() {
    // GIVEN a record containing an alert message with an undefined description level
    val fragment = byteArrayOf(AlertMessage.AlertLevel.WARNING.code.toByte(), UNKNOWN_DESCRIPTION)

    // WHEN parsing the record
    val thrown =
      assertThrows<HandshakeException> {
        AlertMessage.fromByteArray(fragment)
        fail("Should have thrown ${HandshakeException::class.simpleName}")
      }

    // THEN a fatal handshake exception will be thrown
    assertEquals(AlertMessage.AlertLevel.FATAL, thrown.alert.level)
  }

  @Test
  @Throws(IOException::class, ClassNotFoundException::class)
  fun testSerializeWithHandshakeException() {
    val alert = AlertMessage(AlertMessage.AlertLevel.WARNING, AlertMessage.AlertDescription.HANDSHAKE_FAILURE)
    val exception = HandshakeException(alert, "test")

    val out = ByteArrayOutputStream()
    val oout = ObjectOutputStream(out)
    oout.writeObject(exception)

    val bi = ByteArrayInputStream(out.toByteArray())
    val oi = ObjectInputStream(bi)
    val obj = oi.readObject()

    assertInstanceOf(HandshakeException::class.java, obj)
    val readException = obj as HandshakeException
    assertEquals(exception.message, readException.message)
    assertEquals(exception.alert.level, readException.alert.level)
    assertEquals(exception.alert.description, readException.alert.description)
  }
}
