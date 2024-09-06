/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.util

import io.kaxis.exception.VersionMismatchException
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import java.util.concurrent.TimeUnit

object SerializationUtil {
  private val LOGGER: Logger = LoggerFactory.getLogger(SerializationUtil::class.java)

  const val NO_VERSION = 0

  private const val ADDRESS_VERSION = 1

  private const val ADDRESS_LITERAL = 1

  private const val ADDRESS_NAME = 2

  private const val ATTRIBUTES_STRING = 1

  private const val ATTRIBUTES_BYTES = 2

  private const val ATTRIBUTES_INTEGER = 3

  private const val ATTRIBUTES_LONG = 4

  private const val ATTRIBUTES_BOOLEAN = 5

  private const val NANOTIME_SNYC_MARK_VERSION = 1

  /**
   * Write no item to output stream.
   * @param out output stream.
   * @throws IOException if an i/o error occurred
   */
  @Throws(IOException::class)
  fun writeNoItem(out: OutputStream) {
    out.write(NO_VERSION)
  }

  /**
   * Write no item to writer.
   * @param writer writer
   */
  fun writeNoItem(writer: DatagramWriter) {
    writer.writeByte(NO_VERSION.toByte())
  }

  /**
   * Write start of item.
   * @param writer writer
   * @param version version of item's serialization
   * @param numBits number of bits for the item length
   * @return position of the item length
   */
  fun writeStartItem(
    writer: DatagramWriter,
    version: Int,
    numBits: Int,
  ): Int {
    require(version != NO_VERSION) { "version must not be $NO_VERSION!" }
    writer.writeByte(version.toByte())
    return writer.space(numBits)
  }

  /**
   * Write finished.
   * @param writer writer
   * @param position position returned by [writeStartItem].
   * @param numBits number of bits for the item length used for [writeStartItem].
   */
  fun writeFinishedItem(
    writer: DatagramWriter,
    position: Int,
    numBits: Int,
  ) {
    writer.writeSize(position, numBits)
  }

  /**
   * Read item start.
   *
   * **Note**: on version mismatch, it's not supported to retry with a different version! Use [readStartItem] instead!
   * @param reader reader
   * @param version version of item's serialization
   * @param numBits number of bits for the item length
   * @throws VersionMismatchException if version doesn't match.
   * @throws IllegalArgumentException if the read length exceeds the available bytes.
   */
  fun readStartItem(
    reader: DataStreamReader,
    version: Int,
    numBits: Int,
  ): Int {
    require(version != NO_VERSION) { "Version must not be $NO_VERSION!" }
    val read = reader.readNextByte().toInt() and 0xff
    if (read == NO_VERSION) {
      return -1
    } else if (read != version) {
      throw VersionMismatchException("Version mismatch! $version is required, not $read!", read)
    }
    return reader.read(numBits)
  }

  /**
   * Read item start.
   * ```
   * val VERSIONS = SupportedVersions(V1, V2, V3)
   * ...
   * val matcher = VERSIONS.matcher()
   * val len = readStartItem(reader, matcher, 16)
   * ...
   * matcher.readVersion
   * ```
   *
   * @param reader reader
   * @param versions supported versions matcher
   * @param numBits number of bits for the item length
   * @return length of the item, or `-1`, if [writeNoItem] was used.
   * @throws VersionMismatchException if version doesn't match.
   * @throws IllegalArgumentException if the read length exceeds the available bytes.
   */
  fun readStartItem(
    reader: DataStreamReader,
    versions: SupportedVersionsMatcher?,
    numBits: Int,
  ): Int {
    requireNotNull(versions) { "Version must not be null!" }
    val read = reader.readNextByte().toInt() and 0xff
    if (read == NO_VERSION) {
      return -1
    } else if (!versions.supports(read)) {
      throw VersionMismatchException("Version mismatch! $versions are required, not $read!", read)
    }
    return reader.read(numBits)
  }

  /**
   * Write [String] using [StandardCharsets.UTF_8]
   *
   * @param writer writer to write to.
   * @param value value to write.
   * @param numBits number of bits for encoding the length.
   */
  fun write(
    writer: DatagramWriter,
    value: String?,
    numBits: Int,
  ) {
    writer.writeVarBytes(value?.toByteArray(), numBits)
  }

  /**
   * Read [String] using [StandardCharsets.UTF_8].
   * @param reader reader to read.
   * @param numBits number of bits for encoding the length.
   * @return String, or `null`, if size was 0.
   *
   */
  fun readString(
    reader: DatagramReader,
    numBits: Int,
  ): String? {
    val data = reader.readVarBytes(numBits)
    return data?.let { String(it, StandardCharsets.UTF_8) }
  }

  /**
   * Verify [String] using [StandardCharsets.UTF_8].
   * @param reader reader to read.
   * @param expectedValue expected value to verify.
   * @param numBits number of bits for encoding the length.
   * @return `true`, if verify mark is read, `false`, if `null` is read.
   * @throws NullPointerException if the provided expected value is `null`
   * @throws IllegalArgumentException if read value doesn't match expected value
   */
  fun verifyString(
    reader: DatagramReader,
    expectedValue: String?,
    numBits: Int,
  ): Boolean {
    var expectedValue0 = expectedValue
    requireNotNull(expectedValue0) { "Expected value must not be null!" }
    val data = reader.readVarBytes(numBits)
    val mark = expectedValue0.toByteArray()
    if (mark.contentEquals(data)) {
      return true
    }
    val read = Utility.toDisplayString(data, 16)
    if (!read.startsWith("\"") && !read.startsWith("<")) {
      expectedValue0 = Utility.byteArray2HexString(mark, ' ', 16)
    }
    throw IllegalArgumentException("Mismatch, read $read, expected $expectedValue0.")
  }

  /**
   * Write inet socket address.
   * @param writer writer to write to.
   * @param address inet socket address.
   */
  fun write(
    writer: DatagramWriter,
    address: InetSocketAddress?,
  ) {
    if (address == null) {
      writeNoItem(writer)
    } else {
      val position = writeStartItem(writer, ADDRESS_VERSION, Byte.SIZE_BITS)
      writer.write(address.port, Short.SIZE_BITS)
      if (address.isUnresolved) {
        writer.writeByte(ADDRESS_NAME.toByte())
        writer.writeBytes(address.hostName.toByteArray())
      } else {
        writer.writeByte(ADDRESS_LITERAL.toByte())
        writer.writeBytes(address.address.address)
      }
      writeFinishedItem(writer, position, Byte.SIZE_BITS)
    }
  }

  /**
   * Read inet socket address.
   * @param reader reader to read
   * @return read inet socket address, or `null`, if no address was written.
   */
  fun readAddress(reader: DataStreamReader): InetSocketAddress? {
    val length = readStartItem(reader, ADDRESS_VERSION, Byte.SIZE_BITS)
    if (length <= 0) return null
    val rangeReader = reader.createRangeReader(length)
    val port = rangeReader.read(Short.SIZE_BITS)
    val type = rangeReader.readNextByte().toInt() and 0xff
    val address = rangeReader.readBytesLeft()
    return when (type) {
      ADDRESS_NAME -> InetSocketAddress(String(address, StandardCharsets.US_ASCII), port)
      ADDRESS_LITERAL -> InetSocketAddress(InetAddress.getByAddress(address), port)
      else -> null
    }
  }

  /**
   * Write nanotime synchronization mark. Write [System.currentTimeMillis] and [ClockUtil.nanoRealtime]
   * to align uptime with system-time on reading.
   * @param writer writer to write to.
   */
  fun writeNanotimeSynchronizationMark(writer: DatagramWriter) {
    val position = writeStartItem(writer, NANOTIME_SNYC_MARK_VERSION, Byte.SIZE_BITS)
    val millis = System.currentTimeMillis()
    val nanos = ClockUtil.nanoRealtime()
    writer.writeLong(millis, Long.SIZE_BITS)
    writer.writeLong(nanos, Long.SIZE_BITS)
    writeFinishedItem(writer, position, Byte.SIZE_BITS)
  }

  /**
   * Read nanotime synchronization mark. The delta considers different uptimes of hosts, e.g. because the one
   * host runs for a week, the other for a day. It also uses the [System.currentTimeMillis] in order to
   * include the past calender time between writing and reading.
   * @param reader reader to read
   * @return delta in nanoseconds for nanotime synchronization. Considers different uptimes and past calendar time.
   * @throws IllegalArgumentException if version doesn't match or the read length exceeds the available bytes
   */
  fun readNanotimeSynchronizationMark(reader: DataStreamReader): Long {
    val length = readStartItem(reader, NANOTIME_SNYC_MARK_VERSION, Byte.SIZE_BITS)
    if (length <= 0) {
      return 0
    }
    val rangeReader = reader.createRangeReader(length)
    val millis = rangeReader.readLong(Long.SIZE_BITS)
    val nanos = rangeReader.readLong(Long.SIZE_BITS)
    rangeReader.assertFinished("times")
    val startMillis = System.currentTimeMillis()
    val startNanos = ClockUtil.nanoRealtime()
    val deltaSystemTime = TimeUnit.MILLISECONDS.toNanos(startMillis - millis).coerceAtLeast(0L)
    val deltaUptime = startNanos - nanos
    val delta = deltaUptime - deltaSystemTime
    return delta
  }

  /**
   * Skip items until "no item" is read.
   * @param input stream to skip items.
   * @param numBits number of bits of the item length.
   * @throws IllegalArgumentException if stream isn't a valid stream of items
   */
  fun skipItems(
    input: InputStream,
    numBits: Int,
  ) {
    val reader = DataStreamReader(input)
    skipItems(reader, numBits)
  }

  /**
   * Skip items until "no item" is read and return the number.
   * @param reader stream reader to skip items.
   * @param numBits number of bits of the item length.
   * @return number of skipped items.
   * @throws IllegalArgumentException if stream isn't a valid stream of items
   */
  fun skipItems(
    reader: DataStreamReader,
    numBits: Int,
  ): Int {
    var count = 0
    while ((reader.readNextByte().toInt() and 0xff) != NO_VERSION) {
      val len = reader.read(numBits)
      skipBits(reader, (len * Byte.SIZE_BITS).toLong())
      ++count
    }
    return count
  }

  /**
   * Skip bits. If not enough bits are available without blocking, try to read a byte. That seems to be required for [javax.crypto.CipherInputStream]
   * @param reader reader to skip bits.
   * @param numBits number of bits to be skipped
   * @return number of actual skipped bits
   * @throws IllegalArgumentException if not enough bits are available
   */
  fun skipBits(
    reader: DataStreamReader,
    numBits: Long,
  ): Long {
    var bits = numBits
    while (bits > 0) {
      val skipped = reader.skip(bits)
      if (skipped <= 0) {
        // CipherInputStream seems to require that
        // readNextByte fails with IllegalArgumentException
        // at the End of Stream
        reader.readNextByte()
        bits -= Byte.SIZE_BITS
      } else {
        bits -= skipped
      }
    }
    return numBits - bits
  }

  /**
   * Supported versions.
   */
  class SupportedVersionsMatcher(vararg versions: Int) : SupportedVersions(false, *versions) {
    var readVersion: Int

    init {
      this.readVersion = NO_VERSION
    }

    override fun supports(readVersion: Int): Boolean {
      return if (super.supports(readVersion)) {
        this.readVersion = readVersion
        true
      } else {
        this.readVersion = NO_VERSION
        false
      }
    }
  }

  /**
   * Supported versions. Intended to be used as factory for SupportedVersionsMatcher using [matcher]
   */
  open class SupportedVersions {
    /**
     * List of supported version.
     */
    val versions: IntArray

    constructor(vararg versions: Int) : this(true, *versions)

    protected constructor(copy: Boolean, vararg versions: Int) {
      require(versions.isNotEmpty()) { "Versions must not be empty!" }
      this.versions = if (copy) versions.copyOf() else versions
      require(!supports(readVersion = NO_VERSION)) { "Versions must not contain NO_VERSION!" }
    }

    /**
     * Check, if read version is supported.
     * @param readVersion read version
     * @return `true`, if the read version is supported, `false`, otherwise.
     */
    open fun supports(readVersion: Int): Boolean {
      versions.forEach { version ->
        if (readVersion == version) {
          return true
        }
      }
      return false
    }

    override fun toString(): String {
      return versions.contentToString()
    }

    /**
     * Create matcher based on this supported versions.
     * @return matcher
     */
    fun matcher(): SupportedVersionsMatcher = SupportedVersionsMatcher(*versions)
  }
}
