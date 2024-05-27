/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.util

import io.kaxis.Bytes
import javax.crypto.SecretKey

/**
 * Utility to use serialize and deserialize standard type using [DatagramWriter] and [DatagramReader].
 */
object SecretSerializationUtil {
  /**
   * Write secret key.
   * @param writer writer to write to.
   * @param key secret key to write.
   */
  fun write(
    writer: DatagramWriter,
    key: SecretKey?,
  ) {
    if (key == null || SecretUtil.isDestroyed(key)) {
      writer.writeVarBytes(null as ByteArray?, Byte.SIZE_BITS)
    } else {
      val encoded = key.encoded
      writer.writeVarBytes(encoded, Byte.SIZE_BITS)
      Bytes.clear(encoded)
      SerializationUtil.write(writer, key.algorithm, Byte.SIZE_BITS)
    }
  }

  /**
   * Read secret key.
   * @param reader reader to reader
   * @return read secret key, or `null`, if `null` was written.
   * @throws IllegalArgumentException if the data is erroneous
   */
  fun readSecretKey(reader: DatagramReader): SecretKey? {
    var key: SecretKey? = null
    val data = reader.readVarBytes(Byte.SIZE_BITS)
    if (data != null) {
      require(data.isNotEmpty()) { "key must not be empty!" }

      try {
        val algo = SerializationUtil.readString(reader, Byte.SIZE_BITS)
        requireNotNull(algo) { "key must have algorithm!" }
        key = SecretUtil.create(data, algo.intern())
      } finally {
        Bytes.clear(data)
      }
    }
    return key
  }

  /**
   * Write iv.
   * @param writer writer to write to.
   * @param iv iv to write.
   */
  fun write(
    writer: DatagramWriter,
    iv: SecretIvParameterSpec?,
  ) {
    if (iv == null || SecretUtil.isDestroyed(iv)) {
      writer.write(0, Byte.SIZE_BITS)
    } else {
      writer.write(iv.size, Byte.SIZE_BITS)
      iv.writeTo(writer)
    }
  }

  /**
   * Read iv.
   * @param reader reader to read
   * @return read iv, or `null`, if size was 0.
   */
  fun readIv(reader: DatagramReader): SecretIvParameterSpec? {
    val data = reader.readVarBytes(Byte.SIZE_BITS)
    return if (data != null) {
      val iv = SecretUtil.createIv(data)
      Bytes.clear(data)
      iv
    } else {
      null
    }
  }
}
