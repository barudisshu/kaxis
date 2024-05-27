/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.util

import io.kaxis.Bytes.Companion.EMPTY_BYTES
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URI
import java.net.URISyntaxException
import java.net.UnknownHostException

internal class UtilityTest {
  @Test
  fun testHex2ByteArray() {
    val line = "4130010A"
    val result = Utility.hex2ByteArray(line)

    assertArrayEquals(byteArrayOf(0x41, 0x30, 0x01, 0x0a), result)
  }

  @Test
  fun testByteArray2Hex() {
    val data = byteArrayOf(0x41, 0x30, 0x01, 0x0a)
    val result = Utility.byteArray2Hex(data)
    assertEquals("4130010A", result)
  }

  @Test
  fun testHex2CharArray() {
    val line = "4130010A"
    val result = Utility.hex2CharArray(line)
    assertArrayEquals(charArrayOf('A', '0', 0x01.toChar(), '\n'), result)
  }

  @Test
  fun testHex2CharArrayWithNull() {
    val line = null
    val result = Utility.hex2CharArray(line)
    assertNull(result)
  }

  @Test
  fun testHex2CharArrayIllegalArgumentLength() {
    val line = "4130010A0"
    assertThrows<IllegalArgumentException> { Utility.hex2CharArray(line) }
  }

  @Test
  fun testHex2CharArrayIllegalArgumentContent() {
    val line = "4130010A0Z"
    assertThrows<IllegalArgumentException> { Utility.hex2CharArray(line) }
  }

  @Test
  fun testBase64String2ByteArray() {
    val line = "QTABCg==" // hex 4130010A
    val result = Utility.base64ToByteArray(line)
    assertArrayEquals(byteArrayOf(0x41, 0x30, 0x01, 0x0a), result)
  }

  @Test
  fun testByteArray2Base64() {
    val data = byteArrayOf(0x41, 0x30, 0x01, 0x0a)
    val result = Utility.byteArrayToBase64(data)
    assertEquals("QTABCg==", result)
  }

  @Test
  fun testBase64String2ByteArrayPadding() {
    val line = "QTABCg" // hex 4130010A
    val result = Utility.base64ToByteArray(line)
    assertArrayEquals(byteArrayOf(0x41, 0x30, 0x01, 0x0a), result)
  }

  @Test
  fun testBase64String2ByteArrayIllegalLength() {
    val line = "QTABC"
    assertThrows<IllegalArgumentException> { Utility.base64ToByteArray(line) }
  }

  @Test
  fun testBase64String2ByteArrayIllegalCharacter() {
    val line = "QTABC\u0100"
    val result = Utility.base64ToByteArray(line)
    // will change with next major release to IllegalArgumentException
    assertArrayEquals(EMPTY_BYTES, result)
  }

  @Test
  fun testBase64CharArray2ByteArray() {
    val line = "QTABCg==".toCharArray() // hex 4130010A
    val result = Utility.base64ToByteArray(line)
    assertArrayEquals(byteArrayOf(0x41, 0x30, 0x01, 0x0a), result)
  }

  @Test
  fun testByteArray2Base64CharArray() {
    val data = byteArrayOf(0x41, 0x30, 0x01, 0x0a)
    val result = Utility.byteArrayToBase64CharArray(data)
    assertArrayEquals("QTABCg==".toCharArray(), result)
  }

  @Test
  fun testBase64CharArray2ByteArrayPadding() {
    val line = "QTABCg".toCharArray() // hex 4130010A
    val result = Utility.base64ToByteArray(line)
    assertArrayEquals(byteArrayOf(0x41, 0x30, 0x01, 0x0a), result)
  }

  @Test
  fun testBase64CharArray2ByteArrayIllegalLength() {
    val line = "QTABC".toCharArray()
    assertThrows<IllegalArgumentException> { Utility.base64ToByteArray(line) }
  }

  @Test
  fun testBase64CharArray2ByteArrayIllegalCharacter() {
    val line = "QTABC\u0100".toCharArray()
    assertThrows<IllegalArgumentException> { Utility.base64ToByteArray(line) }
  }

  @Test
  @Throws(URISyntaxException::class, UnknownHostException::class)
  fun testGetUriHostname() {
    var hostname = Utility.getUriHostname(InetAddress.getLoopbackAddress())
    assertEquals("127.0.0.1", hostname)

    var test = URI("coap", null, hostname, 5683, null, null, null)
    assertEquals("coap://127.0.0.1:5683", test.toASCIIString())

    hostname = Utility.getUriHostname(Inet6Address.getByName("[FF02::FD]"))
    assertEquals("ff02:0:0:0:0:0:0:fd", hostname)

    test = URI("coap", null, hostname, 5683, null, null, null)
    assertEquals("coap://[ff02:0:0:0:0:0:0:fd]:5683", test.toASCIIString())
  }

  @Test
  @Throws(UnknownHostException::class)
  fun testToHostString() {
    var address = InetSocketAddress("localhost", 5683)
    assertEquals("localhost", Utility.toHostString(address))
    address = InetSocketAddress("127.0.0.1", 5683)
    assertEquals("127.0.0.1", Utility.toHostString(address))
    address = InetSocketAddress.createUnresolved("my.test.server", 5683)
    assertEquals("my.test.server", Utility.toHostString(address))
    val dest = InetAddress.getByAddress(byteArrayOf(8, 8, 8, 8))
    address = InetSocketAddress(dest, 5683)
    assertEquals("8.8.8.8", Utility.toHostString(address))
  }

  @Test
  fun testTrunc() {
    val text = "message"
    val result1 = Utility.trunc(text, 100)
    val result2 = Utility.trunc(text, 4)
    val result3 = Utility.trunc(text, 0)
    assertEquals(text, result1)
    assertEquals("mess", result2)
    assertEquals(text, result3)
  }

  @Test
  fun testTruncateTail() {
    val text = "message"
    val result1 = Utility.truncateTail(text, "agX")
    val result2 = Utility.truncateTail(text, "age")
    val result3 = Utility.truncateTail(text, "")
    assertEquals(text, result1)
    assertEquals("mess", result2)
    assertEquals(text, result3)
  }

  @Test
  fun testTruncateStringBuilderTail() {
    val text1 = StringBuilder("message")
    val text2 = StringBuilder("message")
    val text3 = StringBuilder("message")
    val result1 = Utility.truncateTail(text1, "agX")
    val result2 = Utility.truncateTail(text2, "age")
    val result3 = Utility.truncateTail(text3, "")
    assertFalse(result1)
    assertTrue(result2)
    assertFalse(result3)
    assertEquals("message", text1.toString())
    assertEquals("mess", text2.toString())
    assertEquals("message", text3.toString())
  }

  @Test
  fun testIsPrivateIp() {
    // true
    assertTrue(Utility.isPrivateIp("172.31.255.255")) // true
    assertTrue(Utility.isPrivateIp("172.16.1.2")) // true
    assertTrue(Utility.isPrivateIp("127.0.0.1")) // true
    assertTrue(Utility.isPrivateIp("127.0.0.2")) // true
    assertTrue(Utility.isPrivateIp("192.168.0.1")) // true
    assertTrue(Utility.isPrivateIp("10.0.0.1")) // true
    assertTrue(Utility.isPrivateIp("10.10.1.2")) // true
    assertTrue(Utility.isPrivateIp("169.254.0.0")) // true
    assertTrue(Utility.isPrivateIp("100.126.255.255")) // true (carrier Grade Nat private IP)
    assertTrue(Utility.isPrivateIp("100.96.1.2")) // true (carrier Grade Nat private IP)
    assertTrue(Utility.isPrivateIp("100.64.0.0")) // true (carrier Grade Nat private IP)
    assertTrue(Utility.isPrivateIp("fe80::250:56ff:fe07:e0f4")) // true

    // false
    assertFalse(Utility.isPrivateIp("39.156.69.79")) // false
    assertFalse(Utility.isPrivateIp("fd8f:bda5:99b5:b911::/64")) // false
  }

  @Test
  fun testCarrierGradeNAT() {
    // CarrierGradeNAT: 100.64.0.0 to 100.127.255.255
    // true
    assertTrue(Utility.isCarrierGradeNatIp(InetAddress.getByName("100.64.0.0"))) // true
    assertTrue(Utility.isCarrierGradeNatIp(InetAddress.getByName("100.64.1.0"))) // true
    assertTrue(Utility.isCarrierGradeNatIp(InetAddress.getByName("100.65.0.0"))) // true
    assertTrue(Utility.isCarrierGradeNatIp(InetAddress.getByName("100.126.255.255"))) // true
    assertTrue(Utility.isCarrierGradeNatIp(InetAddress.getByName("100.127.255.254"))) // true
    assertTrue(Utility.isCarrierGradeNatIp(InetAddress.getByName("100.127.255.255"))) // true

    // false
    assertFalse(
      Utility.isCarrierGradeNatIp(InetAddress.getByName("100.128.255.255")),
    ) // false
    assertFalse(
      Utility.isCarrierGradeNatIp(InetAddress.getByName("100.130.255.255")),
    ) // false
    assertFalse(Utility.isCarrierGradeNatIp(InetAddress.getByName("101.64.0.0"))) // false
    assertFalse(Utility.isCarrierGradeNatIp(InetAddress.getByName("250.64.0.0"))) // false

    // fake ipv4
    assertFalse(
      Utility.isCarrierGradeNatIp(InetAddress.getByName("100:126:255:255::")),
    ) // false
    //
    assertFalse(
      Utility.isCarrierGradeNatIp(
        InetAddress.getByName("fe80::250:56ff:fe07:e0f4"),
      ),
    ) // false
  }
}
