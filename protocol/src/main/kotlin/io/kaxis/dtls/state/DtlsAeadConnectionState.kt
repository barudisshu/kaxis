/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.state

import io.kaxis.Bytes
import io.kaxis.dtls.CompressionMethod
import io.kaxis.dtls.DTLSConnectionState
import io.kaxis.dtls.Record
import io.kaxis.dtls.cipher.AeadBlockCipher
import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.util.*
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.GeneralSecurityException
import javax.crypto.SecretKey

/**
 * DTLS connection state for AEAD cipher.
 */
class DtlsAeadConnectionState : DTLSConnectionState {
  companion object {
    private val LOGGER: Logger = LoggerFactory.getLogger(DtlsAeadConnectionState::class.java)
  }

  val encryptionKey: SecretKey?

  val iv: SecretIvParameterSpec?

  /**
   * Initializes all fields with given values.
   * @param cipherSuite the cipher and MAC algorithm to use for encrypting message content
   * @param compressionMethod the algorithm to use for compressing message content
   * @param encryptionKey the secret key to use for encrypting message content
   * @param iv the initialization vector to use for encrypting message content authentication codes (MAC)
   * @throws NullPointerException if any of the parameter is `null`
   */
  constructor(
    cipherSuite: CipherSuite?,
    compressionMethod: CompressionMethod?,
    encryptionKey: SecretKey?,
    iv: SecretIvParameterSpec?,
  ) : super(cipherSuite, compressionMethod) {
    requireNotNull(encryptionKey) { "Encryption key must not be null!" }
    requireNotNull(iv) { "IV must not be null!" }
    this.encryptionKey = SecretUtil.create(encryptionKey)
    this.iv = SecretUtil.createIv(iv)
  }

  /**
   * Create connection state and read specific connection state from provided reader
   * @param cipherSuite cipher suite
   * @param compressionMethod compression method
   * @param reader reader with serialized keys
   */
  constructor(
    cipherSuite: CipherSuite?,
    compressionMethod: CompressionMethod?,
    reader: DatagramReader,
  ) : super(
    cipherSuite,
    compressionMethod,
  ) {
    this.encryptionKey = SecretSerializationUtil.readSecretKey(reader)
    this.iv = SecretSerializationUtil.readIv(reader)
  }

  override fun destroy() {
    SecretUtil.destroy(encryptionKey)
    SecretUtil.destroy(iv)
  }

  override fun isDestroyed(): Boolean {
    return SecretUtil.isDestroyed(iv) && SecretUtil.isDestroyed(encryptionKey)
  }

  override fun encrypt(
    record: Record,
    fragment: ByteArray,
  ): ByteArray {
    /**
     * See [RFC 5246, section 6.2.3.3](http://tools.ietf.org/html/rfc5246#section-6.2.3.3) for explanation of additional data or [RFC 5116, section 2.1](http://tools.ietf.org/html/rfc5116#section-2.1).
     *
     * [TLS AES CCM ECC](http://tools.ietf.org/html/draft-mcgrew-tls-aes-ccm-ecc-03#section-2):
     * ```
     * struct {
     *  case client: uint32 client_write_IV;  // low order 32-bits
     *  case server: uint32 server_write_IV;  // low order 32-bits
     *  uint64 seq_num;
     * } CCMNonce.
     *
     * @param iv the write IV (either client or server).
     * @return the 12 bytes nonce.
     * ```
     */
    fun encryptIv(iv: SecretIvParameterSpec): ByteArray {
      val writer = DatagramWriter(12, true)
      iv.writeTo(writer)
      record.writeExplicitNonce(writer)
      return writer.toByteArray()
    }

    requireNotNull(iv)
    requireNotNull(encryptionKey)

    val nonce = encryptIv(iv)
    val additionalData = record.generateAdditionalData(fragment.size)

    if (LOGGER.isTraceEnabled) {
      LOGGER.trace("encrypt: {} bytes", fragment.size)
      LOGGER.trace("nonce: {}", Utility.byteArray2HexString(nonce))
      LOGGER.trace("adata: {}", Utility.byteArray2HexString(additionalData))
    }

    val encryptedFragment = AeadBlockCipher.encrypt(cipherSuite, encryptionKey, nonce, additionalData, fragment)

    System.arraycopy(nonce, cipherSuite.fixedIvLength, encryptedFragment, 0, cipherSuite.recordIvLength)
    Bytes.clear(nonce)
    LOGGER.trace("==> {} bytes", encryptedFragment.size)

    return encryptedFragment
  }

  override fun decrypt(
    record: Record,
    ciphertextFragment: ByteArray?,
  ): ByteArray {
    requireNotNull(ciphertextFragment) { "Ciphertext must not be null" }
    val recordIvLength = cipherSuite.recordIvLength
    val applicationDataLength = ciphertextFragment.size - recordIvLength - cipherSuite.macLength
    if (applicationDataLength <= 0) {
      throw GeneralSecurityException("Ciphertext too short!")
    }

    requireNotNull(iv)
    requireNotNull(encryptionKey)

    /*
     * See http://tools.ietf.org/html/rfc5246#section-6.2.3.3 and
     * http://tools.ietf.org/html/rfc5116#section-2.1 for an explanation of
     * "additional data" and its structure
     *
     * The decrypted message is always 16/24 bytes shorter than the cipher
     * (8/16 for the authentication tag and 8 for the explicit nonce).
     */
    val additionalData = record.generateAdditionalData(applicationDataLength)
    val writer = DatagramWriter(12, true)
    iv.writeTo(writer)
    writer.writeBytes(ciphertextFragment, 0, recordIvLength)
    val nonce = writer.toByteArray()

    if (LOGGER.isTraceEnabled) {
      LOGGER.trace("decrypt: {} bytes", applicationDataLength)
      LOGGER.trace("nonce: {}", Utility.byteArray2HexString(nonce))
      LOGGER.trace("adata: {}", Utility.byteArray2HexString(additionalData))
    }

    if (LOGGER.isDebugEnabled && AeadBlockCipher.AES_CCM_NO_PADDING == cipherSuite.transformation) {
      // create explicit nonce from values provided in DTLS record
      val explicitNonceUsed = ciphertextFragment.copyOf(recordIvLength)
      // retrieve actual explicit nonce as contained in GenericAEADCipher struct (8 bytes long)
      record.writeExplicitNonce(writer)
      val explicitNonce = writer.toByteArray()
      if (!explicitNonce.contentEquals(explicitNonceUsed)) {
        val sb =
          StringBuilder("The explicit nonce used by the sender does not match the values provided in the DTLS record")
        sb.append(Utility.LINE_SEPARATOR).append("Used    : ").append(Utility.byteArray2HexString(explicitNonceUsed))
        sb.append(Utility.LINE_SEPARATOR).append("Expected: ").append(Utility.byteArray2HexString(explicitNonce))
        LOGGER.debug(sb.toString())
      }
    }
    val payload =
      AeadBlockCipher.decrypt(
        cipherSuite,
        encryptionKey,
        nonce,
        additionalData,
        ciphertextFragment,
        recordIvLength,
        ciphertextFragment.size - recordIvLength,
      )
    Bytes.clear(nonce)
    return payload
  }

  override fun writeTo(writer: DatagramWriter) {
    SecretSerializationUtil.write(writer, encryptionKey)
    SecretSerializationUtil.write(writer, iv)
  }

  override fun toString(): String {
    return StringBuilder("DtlsAeadConnectionState:").apply sb@{
      this@sb.append(Utility.LINE_SEPARATOR)
      val indentation = Utility.indentation(1)
      this@sb.append(indentation).append("Cipher suite: ").append(cipherSuite).append(Utility.LINE_SEPARATOR)
      this@sb.append(indentation).append("Compression method: ").append(compressionMethod)
        .append(Utility.LINE_SEPARATOR)
      this@sb.append(indentation).append("IV: ").append(if (iv == null) "null" else "not null")
        .append(Utility.LINE_SEPARATOR)
      this@sb.append(indentation).append("Encryption key: ").append(if (encryptionKey == null) "null" else "not null")
        .append(Utility.LINE_SEPARATOR)
    }.toString()
  }
}
