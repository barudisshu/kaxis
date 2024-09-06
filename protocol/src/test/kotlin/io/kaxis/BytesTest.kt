/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.SecureRandom
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNotSame

internal class BytesTest {
  inner class TestBytes(bytes: ByteArray, maxLength: Int, copy: Boolean, useClassInEquals: Boolean) :
    Bytes(bytes, maxLength, copy, useClassInEquals)

  @Test
  fun testBytesEquals() {
    val data = byteArrayOf(0, 1, 2, 3)
    val basic = Bytes(data)
    val test = TestBytes(data, 32, copy = true, useClassInEquals = false)
    assertEquals(basic, basic)
    assertEquals(basic, test)
    assertEquals(basic.toString(), test.toString())
    assertEquals(basic.hashCode(), test.hashCode())
    // not the same instance.
    assertNotSame(test, basic)
  }

  @Test
  fun testBytesNotEquals() {
    val data = byteArrayOf(0, 1, 2, 3)
    val basic = Bytes(data)
    val test = TestBytes(data, 32, copy = true, useClassInEquals = true)
    assertNotEquals(basic, test)
    assertNotNull(basic)
    assertNotEquals(basic, Any())
    assertNotSame(test, basic)
  }

  @Test
  fun testBytesNotCloned() {
    val data = byteArrayOf(0, 1, 2, 3)
    val basic = Bytes(data)
    // Note: manipulation is not intended and only done for this test!
    data[0]++
    assertArrayEquals(data, basic.byteArray)
  }

  @Test
  fun testBytesCloned() {
    val data = byteArrayOf(0, 1, 2, 3)
    val basic = Bytes(data, 32, true)
    data[0]++
    assertNotEquals(data[0], basic.byteArray[0])
    assertFalse(basic.isEmpty())
    assertEquals(4, basic.length())
  }

  @Test
  fun testinitException() {
    val data = byteArrayOf(0, 1, 2, 3)
    assertThrows<IllegalArgumentException> { Bytes(null) }
    assertThrows<IllegalArgumentException> { Bytes(data, 2) }
  }

  @Test
  fun testOperatorProcess() {
    val a = Bytes(byteArrayOf(0, 1))
    val b = Bytes(byteArrayOf(2, 3))
    val c = Bytes.concatenate(a, b)
    assertEquals(4, c.size)
  }

  @Test
  fun testCreateRandomBytes() {
    val random = SecureRandom()
    val generate = Bytes.createBytes(random, 16)
    assertEquals(16, generate.size)
  }

  @Test
  fun testCopyOfRangeExact() {
    val bytearray = byteArrayOf(0, 1, 2, 3)
    val copy = ByteArray(4)
    Bytes.copyOfRangeExact(bytearray, 0, 4, copy, 0)
    assertArrayEquals(bytearray, copy)
  }

  @Test
  fun testCopyOfRangeOne() {
    val bytearray = byteArrayOf(0, 1, 2, 3)
    val copy = Bytes.copyOfRangeExact(bytearray, 0, 4)
    assertArrayEquals(bytearray, copy)
  }

  @Test
  fun testArrayStringContains() {
    val data = arrayOf("a", "b", "c")
    assertTrue(Bytes.containsIgnoreCase(data, "A"))
  }

  @Test
  fun testBytesEqual() {
    val data = byteArrayOf(0, 1, 2, 3)
    val basic = Bytes(data)
    val a = TestBytes(data, 32, copy = true, useClassInEquals = true)
    val b = TestBytes(data, 32, copy = true, useClassInEquals = true)
    assertFalse(Bytes.equals(basic, a))
    assertTrue(Bytes.equals(b, a))
  }
}
