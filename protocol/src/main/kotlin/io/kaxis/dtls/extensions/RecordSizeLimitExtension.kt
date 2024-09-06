/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.extensions

import io.kaxis.dtls.message.AlertMessage
import io.kaxis.exception.HandshakeException
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility

/**
 * Record size limit extension. See [RFC 8449](https://tools.ietf.org/html/rfc8449) for additional details.
 */
class RecordSizeLimitExtension(recordSizeLimit: Int) : HelloExtension(ExtensionType.RECORD_SIZE_LIMIT) {
  /**
   * Record size limit to negotiate.
   */
  val recordSizeLimit: Int

  init {
    this.recordSizeLimit = ensureInRange(recordSizeLimit)
  }

  companion object {
    /**
     * Minimum value for record size limit.
     */
    const val MIN_RECORD_SIZE_LIMIT = 64

    /**
     * Maximum value for record size limit.
     */
    const val MAX_RECORD_SIZE_LIMIT = 65535

    /**
     * Number of bits for teh encoded record size limit in the extension.
     */
    private const val RECORD_SIZE_LIMIT_BITS = 16

    /**
     * Create record size limit extension from extensions data bytes.
     * @param extensionDataReader extension data bytes
     * @return created record size limit extension.
     * @throws NullPointerException if extensionData is `null`.
     * @throws HandshakeException if the extension data could not be decoded
     */
    @Throws(HandshakeException::class)
    fun fromExtensionDataReader(extensionDataReader: DatagramReader?): RecordSizeLimitExtension {
      requireNotNull(extensionDataReader) { "record size limit must not be null!" }
      val recordSizeLimit = extensionDataReader.read(RECORD_SIZE_LIMIT_BITS)
      if (recordSizeLimit < MIN_RECORD_SIZE_LIMIT) {
        throw HandshakeException(
          AlertMessage(
            AlertMessage.AlertLevel.FATAL,
            AlertMessage.AlertDescription.ILLEGAL_PARAMETER,
          ),
          "record size limit must be at last $MIN_RECORD_SIZE_LIMIT bytes, not only $recordSizeLimit!",
        )
      }
      return RecordSizeLimitExtension(recordSizeLimit)
    }

    /**
     * Ensure, that provided record limit is between [MIN_RECORD_SIZE_LIMIT] and [MAX_RECORD_SIZE_LIMIT].
     * @param recordSizeLimit record size limit to ensure, that the value is in range.
     * @return [RecordSizeLimitExtension] the provided value, if in range
     * @throws IllegalArgumentException if value is not in range
     */
    fun ensureInRange(recordSizeLimit: Int): Int {
      require(recordSizeLimit in MIN_RECORD_SIZE_LIMIT..MAX_RECORD_SIZE_LIMIT) {
        "Record size limit must be within [$MIN_RECORD_SIZE_LIMIT ... $MAX_RECORD_SIZE_LIMIT], not $recordSizeLimit!"
      }
      return recordSizeLimit
    }
  }

  override val extensionLength: Int
    get() {
      // 2 bytes record size limit
      return RECORD_SIZE_LIMIT_BITS / Byte.SIZE_BITS
    }

  override fun writeExtensionTo(writer: DatagramWriter) {
    writer.write(recordSizeLimit, RECORD_SIZE_LIMIT_BITS)
  }

  override fun toString(indent: Int): String {
    return StringBuilder(super.toString(indent)).apply sb@{
      val indentation = Utility.indentation(indent + 1)
      this@sb.append(indentation).append("Record Size Limit: ").append(recordSizeLimit).append(" bytes")
        .append(Utility.LINE_SEPARATOR)
    }.toString()
  }
}
