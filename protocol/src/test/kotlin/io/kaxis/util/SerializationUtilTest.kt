/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.util

import io.kaxis.rule.TestTimeExtension
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import java.net.InetSocketAddress
import java.util.concurrent.TimeUnit

@ExtendWith(TestTimeExtension::class)
internal class SerializationUtilTest {
  companion object {
    private val MILLISECOND_IN_NANOS: Long = TimeUnit.MILLISECONDS.toNanos(1)
  }

  lateinit var writer: DatagramWriter
  lateinit var reader: DatagramReader

  @BeforeEach
  fun setUp() {
    writer = DatagramWriter()
  }

  @Test
  fun testStrings() {
    val write = "Hallo!"
    SerializationUtil.write(writer, write, Byte.SIZE_BITS)
    swap()
    val read = SerializationUtil.readString(reader, Byte.SIZE_BITS)
    assertEquals(write, read)
  }

  @Test
  fun testNullStrings() {
    val write = null
    SerializationUtil.write(writer, write, Byte.SIZE_BITS)
    swap()
    val read = SerializationUtil.readString(reader, Byte.SIZE_BITS)
    assertEquals(write, read)
  }

  @Test
  fun testEmptyStrings() {
    val write = ""
    SerializationUtil.write(writer, write, Byte.SIZE_BITS)
    swap()
    val read = SerializationUtil.readString(reader, Byte.SIZE_BITS)
    assertEquals(write, read)
  }

  @Test
  fun testAddressIpv4() {
    val write = InetSocketAddress("192.168.1.5", 5683)
    SerializationUtil.write(writer, write)
    swap()
    val read = SerializationUtil.readAddress(reader)
    assertEquals(write, read)
  }

  @Test
  fun testAddressUnresolved() {
    val write = InetSocketAddress("non-existing.host", 11111)
    SerializationUtil.write(writer, write)
    swap()
    val read = SerializationUtil.readAddress(reader)
    assertEquals(write, read)
  }

  @Test
  fun testAddressIpv6() {
    val write = InetSocketAddress("[2001::1]", 5684)
    SerializationUtil.write(writer, write)
    swap()
    val read = SerializationUtil.readAddress(reader)
    assertEquals(write, read)
  }

  @Test
  fun testSkipItems() {
    var pos = SerializationUtil.writeStartItem(writer, 10, Short.SIZE_BITS)
    writer.writeVarBytes("hello".toByteArray(), Byte.SIZE_BITS)
    SerializationUtil.writeFinishedItem(writer, pos, Short.SIZE_BITS)
    pos = SerializationUtil.writeStartItem(writer, 10, Short.SIZE_BITS)
    writer.writeVarBytes(",".toByteArray(), Byte.SIZE_BITS)
    SerializationUtil.writeFinishedItem(writer, pos, Short.SIZE_BITS)
    pos = SerializationUtil.writeStartItem(writer, 10, Short.SIZE_BITS)
    writer.writeVarBytes("world!".toByteArray(), Byte.SIZE_BITS)
    SerializationUtil.writeFinishedItem(writer, pos, Short.SIZE_BITS)
    SerializationUtil.writeNoItem(writer)
    pos = SerializationUtil.writeStartItem(writer, 10, Short.SIZE_BITS)
    writer.writeVarBytes("Next!".toByteArray(), Byte.SIZE_BITS)
    SerializationUtil.writeFinishedItem(writer, pos, Short.SIZE_BITS)
    SerializationUtil.writeNoItem(writer)
    swap()
    var len = SerializationUtil.readStartItem(reader, 10, Short.SIZE_BITS)
    var data = reader.readVarBytes(Byte.SIZE_BITS)
    assertArrayEquals("hello".toByteArray(), data)
    assertEquals(data.size + 1, len) // size of var-bytes
    val count = SerializationUtil.skipItems(reader, Short.SIZE_BITS)
    assertEquals(2, count)
    len = SerializationUtil.readStartItem(reader, 10, Short.SIZE_BITS)
    data = reader.readVarBytes(Byte.SIZE_BITS)
    assertArrayEquals("Next!".toByteArray(), data)
  }

  @Test
  fun testSkipBitsEndOfStream() {
    val pos = SerializationUtil.writeStartItem(writer, 10, Short.SIZE_BITS)
    writer.writeVarBytes("hello".toByteArray(), Byte.SIZE_BITS)
    SerializationUtil.writeFinishedItem(writer, pos, Short.SIZE_BITS)
    swap()
    assertThrows<IllegalArgumentException> { SerializationUtil.skipBits(reader, 1024) }
  }

  private fun swap() {
    reader = DatagramReader(writer.toByteArray())
  }
}
