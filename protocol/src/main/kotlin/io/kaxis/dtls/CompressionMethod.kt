/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls

import io.kaxis.dtls.CompressionMethod.NULL
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * An identifier for the compression algorithms defined by the IANA to be used with DTLS.
 *
 * Instances of this enumeration do not implement any compression functionality. They merely serve as an object
 * representation of the identifiers defined in [Transport Layer Security Protocol Compression Methods](https://tools.ietf.org/html/rfc3749).
 *
 * Note, that only the [NULL] compression method is supported.
 */
enum class CompressionMethod(val code: Int) {
  NULL(0x00),
  DEFAULT(0x01),
  ;

  companion object {
    private val LOGGER: Logger = LoggerFactory.getLogger(CompressionMethod::class.java)
    const val COMPRESSION_METHOD_BITS = 8

    fun getMethodByCode(code: Int): CompressionMethod? {
      return when (code) {
        0x00 -> NULL
        0x01 -> DEFAULT
        else -> null
      }
    }

    /**
     * Write a list of compression methods.
     * @param writer writer to write to
     * @param compressionMethods the list of compression methods
     */
    fun listToWriter(
      writer: DatagramWriter,
      compressionMethods: List<CompressionMethod>,
    ) {
      compressionMethods.forEach { compressionMethod ->
        writer.write(compressionMethod.code, COMPRESSION_METHOD_BITS)
      }
    }

    /**
     * Takes a reader and creates the representing list of compression methods.
     * @param reader the encoded compression methods as byte array
     * @return corresponding list of compression methods
     */
    fun listFromReader(reader: DatagramReader): MutableList<CompressionMethod> {
      return arrayListOf<CompressionMethod>().apply compressionMethods@{
        while (reader.bytesAvailable()) {
          val code = reader.read(COMPRESSION_METHOD_BITS)
          val method = getMethodByCode(code)
          if (method != null) {
            this@compressionMethods.add(method)
          }
        }
      }
    }
  }
}
