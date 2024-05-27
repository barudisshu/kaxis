/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls

import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.dtls.state.DtlsAeadConnectionState
import io.kaxis.dtls.state.DtlsBlockConnectionState
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.SecretIvParameterSpec
import io.kaxis.util.Utility
import java.security.GeneralSecurityException
import javax.crypto.SecretKey
import javax.security.auth.Destroyable

/**
 * A set of algorithms and corresponding security parameters that together represent the _current read_ or _write_
 * state of a TLS connection.
 *
 * According to the [TLS 1.2](https://tools.ietf.org/html/rfc5246#section-6.1) specification, a connection state _`specifies
 * a compression algorithm, an encryption algorithm, and a MAC algorithm. In addition, the parameters for these algorithms
 * are known; the MAC key and the bulk encryption keys for the connection in both the read and the write directions`_.
 *
 * This class is immutable and thus only appropriate to reflect a current read or write state whose properties have
 * been negotiated/established already.
 */
abstract class DTLSConnectionState : Destroyable {
  companion object {
    @JvmField
    val NULL =
      object : DTLSConnectionState(CipherSuite.TLS_NULL_WITH_NULL_NULL, CompressionMethod.NULL) {
        override fun encrypt(
          record: Record,
          fragment: ByteArray,
        ): ByteArray = fragment

        override fun decrypt(
          record: Record,
          ciphertextFragment: ByteArray?,
        ): ByteArray? = ciphertextFragment

        override fun toString(): String {
          return StringBuilder("DtlsNullConnectionState:").apply sb@{
            this@sb.append(Utility.LINE_SEPARATOR).append("\tCipher suite: ").append(cipherSuite)
            this@sb.append(Utility.LINE_SEPARATOR).append("\tCompression method: ").append(compressionMethod)
          }.toString()
        }

        override fun destroy() {}

        override fun isDestroyed(): Boolean {
          return false
        }

        override fun writeTo(writer: DatagramWriter) {
          throw IllegalStateException("No supported!")
        }
      }

    /**
     * Create connection state and initializes all fields with given values.
     * @param cipherSuite the cipher and MAC algorithm to use for encrypting message content
     * @param compressionMethod the algorithm to use for compressing message content
     * @param encryptionKey the secret key to use for encrypting message content
     * @param iv the initialization vector to use for encrypting message content
     * @param macKey the key to use for creating/verifying message authentication codes (MAC)
     * @return create connection state.
     * @throws NullPointerException if any of the parameter used by the provided cipher suite is `null`
     */
    @JvmStatic
    fun create(
      cipherSuite: CipherSuite?,
      compressionMethod: CompressionMethod?,
      encryptionKey: SecretKey?,
      iv: SecretIvParameterSpec?,
      macKey: SecretKey?,
    ): DTLSConnectionState {
      return when (cipherSuite?.cipherType) {
        CipherSuite.CipherType.NULL -> NULL
        CipherSuite.CipherType.BLOCK -> DtlsBlockConnectionState(cipherSuite, compressionMethod, encryptionKey, macKey)
        CipherSuite.CipherType.AEAD -> DtlsAeadConnectionState(cipherSuite, compressionMethod, encryptionKey, iv)
        else -> throw IllegalArgumentException("cipher type ${cipherSuite?.cipherType} not supported!")
      }
    }

    /**
     * Read cipher suite specific connection state from reader.
     * @param cipherSuite cipher suite
     * @param compressionMethod compression method
     * @param reader reader with data
     * @return connection state
     */
    @JvmStatic
    fun fromReader(
      cipherSuite: CipherSuite?,
      compressionMethod: CompressionMethod?,
      reader: DatagramReader,
    ): DTLSConnectionState {
      return when (cipherSuite?.cipherType) {
        CipherSuite.CipherType.BLOCK -> DtlsBlockConnectionState(cipherSuite, compressionMethod, reader)
        CipherSuite.CipherType.AEAD -> DtlsAeadConnectionState(cipherSuite, compressionMethod, reader)
        else -> throw IllegalArgumentException("cipher type ${cipherSuite?.cipherType} not supported!")
      }
    }
  }

  val cipherSuite: CipherSuite

  /**
   * Gets the algorithm used for reducing the size of _plaintext_ data to be exchanged with a peer by means of
   * TLS _APPLICATION_DATA_ messages.
   * @return the algorithm identifier
   */
  val compressionMethod: CompressionMethod

  /**
   * Initializes all fields with given values.
   * @param cipherSuite the cipher and MAC algorithm to use for encrypting message content
   * @param compressionMethod the algorithm to use for compressing message content
   * @throws NullPointerException if any of the parameter is `null`
   */
  constructor(cipherSuite: CipherSuite?, compressionMethod: CompressionMethod?) {
    requireNotNull(cipherSuite) { "Cipher suite must not be null" }
    requireNotNull(compressionMethod) { "Compression method must not be null" }
    this.cipherSuite = cipherSuite
    this.compressionMethod = compressionMethod
  }

  /**
   * Checks whether the cipher suite is not the `NULL_CIPHER`.
   * @return `true` if the suite is [CipherSuite.isValidForNegotiation]
   */
  val hasValidCipherSuite: Boolean
    get() = cipherSuite.isValidForNegotiation

  /**
   * Encrypt fragment for provided record.
   * @param record record to encrypt fragment for
   * @param fragment fragment to encrypt
   * @return encrypted fragment
   * @throws GeneralSecurityException if an error occurred during encryption
   */
  @Throws(GeneralSecurityException::class)
  abstract fun encrypt(
    record: Record,
    fragment: ByteArray,
  ): ByteArray

  /**
   * Decrypt fragment for provided record.
   * @param record record to decrypt fragment for
   * @param ciphertextFragment encrypted fragment
   * @return fragment
   * @throws GeneralSecurityException if an error occurred during decryption
   */
  @Throws(GeneralSecurityException::class)
  abstract fun decrypt(
    record: Record,
    ciphertextFragment: ByteArray?,
  ): ByteArray?

  /**
   * Write cipher suite specific connection state to writer.
   *
   * **Note**: the stream will contain not encrypted critical credentials. It is required to protect this data before exporting it.
   * @param writer writer to write state to.
   */
  abstract fun writeTo(writer: DatagramWriter)
}
