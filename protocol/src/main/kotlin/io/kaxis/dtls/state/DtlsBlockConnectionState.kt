/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.state

import io.kaxis.dtls.CompressionMethod
import io.kaxis.dtls.DTLSConnectionState
import io.kaxis.dtls.Record
import io.kaxis.dtls.cipher.CbcBlockCipher
import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.util.*
import java.security.GeneralSecurityException
import javax.crypto.SecretKey

/**
 * DTLS connection state for block cipher.
 */
class DtlsBlockConnectionState : DTLSConnectionState {
  private val encryptionKey: SecretKey?

  private val macKey: SecretKey?
    get() = SecretUtil.create(field)

  /**
   * Initializes all fields with given values.
   * @param cipherSuite the cipher and MAC algorithm to use for encrypting message content
   * @param compressionMethod the algorithm to use for compressing message content
   * @param encryptionKey the secret key to use for encrypting message content
   * @param mackey the key to use for creating/verifying message authentication codes (MAC)
   * @throws NullPointerException if any of the parameter is `null`
   */
  constructor(
    cipherSuite: CipherSuite?,
    compressionMethod: CompressionMethod?,
    encryptionKey: SecretKey?,
    mackey: SecretKey?,
  ) : super(cipherSuite, compressionMethod) {
    requireNotNull(encryptionKey) { "Encryption key must not be null!" }
    requireNotNull(mackey) { "MAC key must not be null!" }
    this.encryptionKey = SecretUtil.create(encryptionKey)
    this.macKey = SecretUtil.create(mackey)
  }

  /**
   * Create connection state and read specific connection state from provided reader
   * @param cipherSuite cipher suite
   * @param compressionMethod compression method
   * @param reader reader with serialized keys
   */
  constructor(cipherSuite: CipherSuite?, compressionMethod: CompressionMethod?, reader: DatagramReader) :
    super(cipherSuite, compressionMethod) {
    this.macKey = SecretSerializationUtil.readSecretKey(reader)
    this.encryptionKey = SecretSerializationUtil.readSecretKey(reader)
  }

  override fun destroy() {
    SecretUtil.destroy(encryptionKey)
    SecretUtil.destroy(macKey)
  }

  override fun isDestroyed(): Boolean {
    return SecretUtil.isDestroyed(macKey) && SecretUtil.isDestroyed(encryptionKey)
  }

  override fun encrypt(
    record: Record,
    fragment: ByteArray,
  ): ByteArray {
    requireNotNull(encryptionKey)
    requireNotNull(macKey)
    val additionalData = record.generateAdditionalData(fragment.size)
    return CbcBlockCipher.encrypt(cipherSuite, encryptionKey, macKey!!, additionalData, fragment)
  }

  override fun decrypt(
    record: Record,
    ciphertextFragment: ByteArray?,
  ): ByteArray {
    requireNotNull(ciphertextFragment) { "Ciphertext must not be null" }
    if (ciphertextFragment.size % cipherSuite.recordIvLength != 0) {
      throw GeneralSecurityException("Ciphertext doesn't fit block size!")
    }
    if (ciphertextFragment.size < cipherSuite.recordIvLength + cipherSuite.macLength + 1) {
      throw GeneralSecurityException("Ciphertext too short!")
    }
    requireNotNull(encryptionKey)
    requireNotNull(macKey)
    // additional data for MAC, use length 0
    // and overwrite it after decryption
    val additionalData = record.generateAdditionalData(0)
    return CbcBlockCipher.decrypt(cipherSuite, encryptionKey, macKey!!, additionalData, ciphertextFragment)
  }

  override fun writeTo(writer: DatagramWriter) {
    SecretSerializationUtil.write(writer, macKey)
    SecretSerializationUtil.write(writer, encryptionKey)
  }

  override fun toString(): String {
    val sb = StringBuilder("DtlsBlockConnectionState: ").append(Utility.LINE_SEPARATOR)
    val indentation = Utility.indentation(1)
    sb.append(indentation).append("Cipher suite: ").append(cipherSuite).append(Utility.LINE_SEPARATOR)
    sb.append(indentation).append("Compression method: ").append(compressionMethod).append(Utility.LINE_SEPARATOR)
    sb.append(indentation).append("MAC key: ").append(if (macKey == null) "null" else "not null")
      .append(Utility.LINE_SEPARATOR)
    sb.append(indentation).append("Encryption key: ").append(if (encryptionKey == null) "null" else "not null")
      .append(Utility.LINE_SEPARATOR)
    return sb.toString()
  }
}
