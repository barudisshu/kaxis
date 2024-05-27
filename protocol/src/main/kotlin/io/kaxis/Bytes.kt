/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis

import io.kaxis.Bytes.Companion.hashCode
import io.kaxis.delegates.NullableDelegates
import io.kaxis.util.Streams
import io.kaxis.util.Utility
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.nio.ByteBuffer
import java.util.*
import kotlin.experimental.and
import kotlin.experimental.or

/**
 * Byte array as a key. (As a decorator of byte array)
 */
open class Bytes {
  /**
   * bytes.
   */
  val byteArray: ByteArray

  /**
   * Pre-calculated hash.
   * @see hashCode
   */
  val hash: Int

  val useClassInEquals: Boolean

  /**
   * Get bytes as (hexadecimal) string.
   * @return bytes as (hexadecimal) string.
   *
   * It's the same as Java
   * ```java
   * public final String getAsString() {
   *   if (asString == null) {
   *     asString = Utilities.byteArray2Hex(byteArray);
   *   }
   *   return asString;
   * }
   * ```
   */
  val asString: String by NullableDelegates { Utility.byteArray2Hex(it.byteArray) }

  /**
   * Create bytes array.
   * @param byteArray bytes (not copied!)
   * @throws NullPointerException if bytes is `null`
   * @throws IllegalArgumentException if bytes length is larger than 255
   */
  constructor(byteArray: ByteArray?) : this(byteArray, 255, false)

  /**
   * Create bytes array.
   * @param byteArray bytes (not copied!)
   * @param maxLength maximum length of bytes.
   * @throws NullPointerException if bytes is `null`
   * @throws IllegalArgumentException if bytes length is larger than maxLength
   */
  constructor(byteArray: ByteArray?, maxLength: Int) : this(byteArray, maxLength, false)

  /**
   * Create bytes array.
   * @param byteArray bytes
   * @param maxLength maximum length of bytes
   * @param copy `true` to copy bytes, `false` to use the provided bytes
   * @throws NullPointerException if bytes is `null`
   * @throws IllegalArgumentException if bytes length is larger than maxLength
   */
  constructor(byteArray: ByteArray?, maxLength: Int, copy: Boolean) : this(byteArray, maxLength, copy, false)

  /**
   * Create bytes array.
   * @param byteArray bytes
   * @param maxLength maximum length of bytes
   * @param copy `true` to copy bytes, `false` to use the provided bytes
   * @param useClassInEquals `true` to check the class, `false`, if equals checks only for [Bytes]
   * @throws NullPointerException if bytes is `null`
   * @throws IllegalArgumentException if bytes length is larger than maxLength
   */
  constructor(byteArray: ByteArray?, maxLength: Int, copy: Boolean, useClassInEquals: Boolean) {
    requireNotNull(byteArray) { "bytes must not be null" }
    require(byteArray.size <= maxLength) { "bytes length must be between 0 and $maxLength inclusive" }
    this.useClassInEquals = useClassInEquals
    this.byteArray = if (copy) Arrays.copyOf(byteArray, byteArray.size) else byteArray
    this.hash = byteArray.contentHashCode()
  }

  override fun toString(): String {
    return "BYTES=$asString"
  }

  override fun hashCode(): Int {
    return hash
  }

  /**
   * **Note**: the sub-class may be ignored. This depends on the provided value of the [useClassInEquals] parameter in [Bytes] for this, or the other object. The default behavior is changed to ignore he sub-class.
   */
  override fun equals(other: Any?): Boolean {
    if (this === other) {
      return true
    } else if (other == null) {
      return false
    }
    if (other is Bytes) {
      if ((useClassInEquals || other.useClassInEquals) && javaClass != other.javaClass) {
        return false
      }
      if (hash != other.hash) {
        return false
      }
      return byteArray.contentEquals(other.byteArray)
    }
    return false
  }

  /**
   * Check, if byte array is empty.
   * @return `true`, if byte array is empty, `false`, otherwise
   */
  fun isEmpty(): Boolean = byteArray.isEmpty()

  fun isNotEmpty(): Boolean = byteArray.isNotEmpty()

  /**
   * Return number of bytes.
   * @return number of bytes. 0 to 255.
   */
  fun length(): Int = byteArray.size

  companion object {
    /**
     * Empty byte array.
     */
    @JvmField
    val EMPTY_BYTES: ByteArray = ByteArray(0)

    @JvmField
    val EMPTY_SHORTS: ShortArray = ShortArray(0)

    @JvmField
    val EMPTY_INTS: IntArray = IntArray(0)

    @JvmField
    val EMPTY_LONGS: LongArray = LongArray(0)

    /**
     * Create byte array initialized with random bytes.
     * @param generator random generator
     * @param size number of bytes
     * @return byte array initialized with random bytes
     * @see Random.nextBytes
     */
    @JvmStatic
    fun createBytes(
      generator: Random,
      size: Int,
    ): ByteArray {
      val byteArray = ByteArray(size)
      try {
        generator.nextBytes(byteArray)
      } catch (ex: IllegalArgumentException) {
        // Bouncy Castle limits the SecureRandom to 32k
        if (ex.message?.contains("Number of bits per request limited ") == true && size > 4096) {
          val part = ByteArray(4096)
          var offset = 0
          while (offset < size) {
            generator.nextBytes(part)
            val fill = (size - offset).coerceAtMost(part.size)
            System.arraycopy(part, 0, byteArray, offset, fill)
            offset += fill
          }
        }
      }
      return byteArray
    }

    /**
     * Concatenates two Bytes.
     * @param a the first Bytes.
     * @param b the second Bytes.
     * @return the concatenated array.
     * @see concatenate(ByteArray, ByteArray): ByteArray
     */
    @JvmStatic
    fun concatenate(
      a: Bytes,
      b: Bytes,
    ): ByteArray = concatenate(a.byteArray, b.byteArray)

    /**
     * Concatenates two byte arrays.
     * @param a the first array.
     * @param b the second array.
     * @return the concatenated array.
     * @see concatenate(Bytes, Bytes): ByteArray
     */
    @JvmStatic
    fun concatenate(
      a: ByteArray,
      b: ByteArray,
    ): ByteArray {
      val lengthA = a.size
      val lengthB = b.size

      val concat = ByteArray(lengthA + lengthB)

      System.arraycopy(a, 0, concat, 0, lengthA)
      System.arraycopy(b, 0, concat, lengthA, lengthB)

      return concat
    }

    /**
     * Clear provided byte array.
     * Fill it with 0s.
     * @param data byte array to be cleared.
     */
    @JvmStatic
    fun clear(data: ByteArray) {
      Arrays.fill(data, 0)
    }

    /**
     * Copy array to target array.
     */
    @JvmStatic
    fun copyOfRangeExact(
      original: ByteArray,
      from: Int,
      to: Int,
      dest: ByteArray,
      offset: Int,
    ) {
      val newLength = to - from
      require(dest.size - offset >= newLength) { "the copy data length exceeds the dest byte array." }
      System.arraycopy(original, from, dest, offset, newLength)
    }

    /**
     * Copy, snippet of byte array.
     * @param original original
     * @param from from
     * @param to to
     * @return new byte array.
     */
    @JvmStatic
    fun copyOfRangeExact(
      original: ByteArray,
      from: Int,
      to: Int,
    ): ByteArray {
      val newLength = to - from
      val copy = ByteArray(newLength)
      System.arraycopy(original, from, copy, 0, newLength)
      return copy
    }

    /**
     * Checks, whether the set contains the value, or not.
     * The check is done using [String.equals]
     * @param set set of strings
     * @param value value to match
     * @return `true` if value is contained in set, `false`, otherwise.
     */
    @JvmStatic
    fun containsIgnoreCase(
      set: Array<String>,
      value: String,
    ): Boolean {
      for (item in set) {
        if (item.equals(value, true)) return true
      }
      return false
    }

    @JvmStatic
    fun equals(
      a: Bytes?,
      b: Bytes?,
    ): Boolean {
      if (a === b) {
        return true
      } else if (a == null || b == null) {
        return false
      }
      return a == b
    }

    @JvmStatic
    fun Short.isValidUint8(): Boolean = (this and 0xFF) == this

    @JvmStatic
    fun Int.isValidUint8(): Boolean = (this and 0xFF) == this

    @JvmStatic
    fun Long.isValidUint8(): Boolean = (this and 0xFFL) == this

    @JvmStatic
    fun Int.isValidUint16(): Boolean = (this and 0xFFFF) == this

    @JvmStatic
    fun Long.isValidUint16(): Boolean = (this and 0xFFFFL) == this

    @JvmStatic
    fun Int.isValidUint24(): Boolean = (this and 0xFFFFFF) == this

    @JvmStatic
    fun Long.isValidUint24(): Boolean = (this and 0xFFFFFL) == this

    @JvmStatic
    fun Long.isValidUint32(): Boolean = (this and 0xFFFFFFFL) == this

    @JvmStatic
    fun Long.isValidUint48(): Boolean = (this and 0xFFFFFFFFFL) == this

    @JvmStatic
    fun Long.isValidUint64(): Boolean = (this and 0xFFFFFFFFFFFL) == this

    /**
     * Read offset data byte into short.
     * @param buf 1 byte.
     * @param offset 0 default
     * @return [Short]
     */
    @JvmStatic
    fun readUint8(
      buf: ByteArray?,
      offset: Int = 0,
    ): Short {
      requireNotNull(buf)
      return (buf[offset].toInt() and 0xff).toShort()
    }

    /**
     * Read uint8.
     */
    @JvmStatic
    @Throws(IOException::class)
    fun readUint8(input: InputStream): Short {
      val i = input.read()
      if (i < 0) {
        throw EOFException()
      }
      return i.toShort()
    }

    /**
     * Read 1 byte(8 bits) unsigned byte data from byte buffer with offset.
     * @param buffer buffer
     * @return [Byte]
     */
    @JvmStatic
    fun readUint8(
      buffer: ByteBuffer,
      offset: Int = buffer.position(),
    ): Byte = buffer[offset].apply { buffer.position(buffer.position() + 1) }

    @JvmStatic
    fun writeUint8(
      s: Short,
      buf: ByteArray,
      offset: Int = 0,
    ) {
      buf[offset] = s.toByte()
    }

    @JvmStatic
    fun writeUint8(
      i: Int,
      buf: ByteArray,
      offset: Int = 0,
    ) {
      buf[offset] = i.toByte()
    }

    @JvmStatic
    fun writeUint8(
      buffer: ByteBuffer,
      data: ByteArray,
    ) {
      buffer.put(data)
    }

    /**
     * Read offset data byte into int. Offset cursor is not change.
     * @param buf 2 bytes
     * @param offset 0
     * @return int.
     */
    @JvmStatic
    fun readUint16(
      buf: ByteArray?,
      offset: Int = 0,
    ): Int {
      requireNotNull(buf)
      require(buf.size >= 2)
      var n = (buf[offset].toInt() and 0xff) shl 8
      n = n or (buf[1 + offset].toInt() and 0xff) // offset + 1 for next byte.
      return n
    }

    /**
     * Read Unsigned int 16.
     */
    @Throws(IOException::class)
    @JvmStatic
    fun readUint16(input: InputStream): Int {
      val i1 = input.read()
      val i2 = input.read()
      if (i2 < 0) {
        throw EOFException()
      }
      return (i1 shl 8) or i2
    }

    /**
     * Read 2 bytes unsigned int data from byte buffer.
     * @param buffer buffer
     * @return int
     */
    @JvmStatic
    fun readUint16(
      buffer: ByteBuffer,
      offset: Int = buffer.position(),
    ): Short =
      (
        ((buffer[offset] and 0xFF.toByte()).toInt() shl 8).toShort()
          or (buffer[offset] and 0xFF.toByte()).toShort()
      )

    @JvmStatic
    fun writeUint16(
      i: Int,
      buf: ByteArray,
      offset: Int = 0,
    ) {
      buf[offset] = (i ushr 8).toByte()
      buf[1 + offset] = i.toByte()
    }

    /**
     * Write 2 bytes unsigned short data to byte buffer.
     * @param buffer buffer
     * @param data short
     */
    @JvmStatic
    fun writeUint16(
      buffer: ByteBuffer,
      data: Short,
    ) {
      buffer.put(((data and 0xFF00.toShort()).toInt() ushr 8).toByte())
      buffer.put((data and 0xFF).toByte())
    }

    /**
     * Read unsigned int 24.
     */
    @Throws(IOException::class)
    @JvmStatic
    fun readUint24(input: InputStream): Int {
      val i1 = input.read()
      val i2 = input.read()
      val i3 = input.read()
      if (i3 < 0) {
        throw EOFException()
      }
      return (i1 shl 16) or (i2 shl 8) or i3
    }

    /**
     * Read 3 bytes unsigned int data from byte buffer.
     * @param buffer buffer
     * @return int
     */
    @JvmStatic
    fun readUint24(
      buffer: ByteBuffer,
      offset: Int = buffer.position(),
    ): Int =
      (
        ((buffer[offset] and 0xFF.toByte()).toInt() shl 16)
          or ((buffer[offset] and 0xFF.toByte()).toInt() shl 8)
          or (buffer[offset] and 0xFF.toByte()).toInt()
      ).apply {
        buffer.position(buffer.position() + 3)
      }

    /**
     * Read 3 bytes unsigned int data from byte array.
     * @param buffer bytes
     * @return int
     */
    @JvmStatic
    fun readUint24(
      buffer: ByteArray,
      offset: Int = 0,
    ): Int =
      (
        ((buffer[offset].toInt() and 0xFF) shl 16)
          or ((buffer[offset + 1].toInt() and 0xFF) shl 8)
          or (buffer[offset + 2].toInt() and 0xFF)
      )

    @JvmStatic
    fun writeUint24(
      i: Int,
      buf: ByteArray,
      offset: Int = 0,
    ) {
      buf[offset] = (i ushr 16).toByte()
      buf[1 + offset] = (i ushr 8).toByte()
      buf[2 + offset] = i.toByte()
    }

    /**
     * Write 3 bytes unsigned integer data to byte buffer.
     * @param buffer buffer
     * @param data integer
     */
    @JvmStatic
    fun writeUint24(
      buffer: ByteBuffer,
      data: Int,
    ) {
      buffer.put(((data and 0xFF0000) ushr 16).toByte())
      buffer.put(((data and 0xFF00) ushr 8).toByte())
      buffer.put((data and 0xFF).toByte())
    }

    @JvmStatic
    fun readUint32(
      buf: ByteArray?,
      offset: Int = 0,
    ): Long {
      requireNotNull(buf)
      require(buf.size >= 4)
      var n = (buf[offset].toLong() and 0xff) shl 24
      n = n or (buf[1 + offset].toLong() and 0xff) shl 16
      n = n or (buf[2 + offset].toLong() and 0xff) shl 8
      n = n or (buf[3 + offset].toLong() and 0xff)
      return n and 0xFFFFFFFFL
    }

    @Throws(IOException::class)
    @JvmStatic
    fun readUint32(input: InputStream): Long {
      val i1 = input.read()
      val i2 = input.read()
      val i3 = input.read()
      val i4 = input.read()
      if (i4 < 0) {
        throw EOFException()
      }
      return ((i1.toLong() shl 24) or (i2.toLong() shl 16) or (i3.toLong() shl 8) or i4.toLong()) and 0xFFFFFFFFL
    }

    /**
     * Read 4 bytes unsigned long data from byte buffer.
     * @param buffer buffer
     * @return long
     */
    @JvmStatic
    fun readUint32(
      buffer: ByteBuffer,
      offset: Int = buffer.position(),
    ): Long =
      (
        ((buffer[offset] and 0xFF.toByte()).toLong() shl 16)
          or ((buffer[offset] and 0xFF.toByte()).toLong() shl 16)
          or ((buffer[offset] and 0xFF.toByte()).toLong() shl 8)
          or (buffer[offset] and 0xFF.toByte()).toLong()
      ).apply {
        buffer.position(buffer.position() + 4)
      }

    @JvmStatic
    fun writeUint32(
      i: Long,
      buf: ByteArray,
      offset: Int = 0,
    ) {
      buf[offset] = (i ushr 24).toByte()
      buf[1 + offset] = (i ushr 16).toByte()
      buf[2 + offset] = (i ushr 8).toByte()
      buf[3 + offset] = i.toByte()
    }

    /**
     * Write 4 bytes unsigned long data to byte buffer.
     * @param buffer buffer
     * @param data long
     */
    @JvmStatic
    fun writeUint32(
      buffer: ByteBuffer,
      data: Long,
    ) {
      buffer.put(((data and 0xFF000000L) ushr 24).toByte())
      buffer.put(((data and 0xFF0000) ushr 16).toByte())
      buffer.put(((data and 0xFF00) ushr 8).toByte())
      buffer.put((data and 0xFF).toByte())
    }

    /**
     * Read fully into net/io.
     * @param length len
     * @param input io stream
     * @return byte array
     * @throws IOException io except
     */
    @Throws(IOException::class)
    @JvmStatic
    fun readFully(
      length: Int,
      input: InputStream,
    ): ByteArray {
      if (length < 1) {
        return EMPTY_BYTES
      }
      val buf = ByteArray(length)
      if (length != Streams.readFully(input, buf)) {
        throw EOFException()
      }
      return buf
    }

    @Throws(IOException::class)
    @JvmStatic
    fun readFully(
      buf: ByteArray,
      input: InputStream,
    ) {
      val length = buf.size
      if (length > 0 && length != Streams.readFully(input, buf)) {
        throw EOFException()
      }
    }

    /**
     * Read 1 byte opaque. Also used commonly in the data length.
     */
    @Throws(IOException::class)
    @JvmStatic
    fun readOpaque8(input: InputStream): ByteArray {
      val length = readUint8(input).toInt()
      return readFully(length, input)
    }
  }
}
