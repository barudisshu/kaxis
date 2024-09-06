/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.cipher

import io.kaxis.Bytes
import io.kaxis.exception.InvalidMacException
import io.kaxis.util.DatagramWriter
import java.security.GeneralSecurityException
import java.security.InvalidKeyException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import kotlin.experimental.xor

/**
 * A Cipher Block Chaining (CBC) block cipher.
 */
object CbcBlockCipher {
  // byte used to fill-up plaintext for extra message digest compression
  private val FILLUP = Bytes.createBytes(SecureRandom(), 256)

  // Static methods ///////////////////////////////////////////////////////

  /**
   * Converts a given TLSCompressed. fragment to a TLSCiphertext.fragment structure as defined by [RFC 5246, section 6.2.3.2](https://tools.ietf.org/html/rfc5246#section-6.2.3.2).
   *
   * ```
   * struct {
   *  opaque IV[SecurityParameters.record_iv_length];
   *  block-ciphered struct {
   *    opaque content[TLSCompressed.length];
   *    opaque MAC[SecurityParameters.mac_length];
   *    uint8 padding[GenericBlockCipher.padding_length];
   *    uint8 padding_length;
   *  };
   * } GenericBlockCipher;
   * ```
   *
   * The particular cipher to use is determined from the negotiated cipher suite in the _current_ DTLS connection state.
   * @param suite used cipher suite
   * @param key encryption key
   * @param macKey mac key
   * @param additionalData additional data. Note: the TLSCompressed. length is not available before decryption. Therefore
   * the last two bytes will be modified with that length after the decryption.
   * @param ciphertext encrypted message including initial vector
   * @return decrypted and authenticated payload.
   * @throws GeneralSecurityException if the plaintext could not be decrypted
   * @throws InvalidMacException if message authentication failed
   *
   */
  @Throws(GeneralSecurityException::class)
  fun decrypt(
    suite: CipherSuite,
    key: SecretKey,
    macKey: SecretKey,
    additionalData: ByteArray,
    ciphertext: ByteArray,
  ): ByteArray {
    /*
     * see http://tools.ietf.org/html/rfc5246#section-6.2.3.2 for explanation
     */

    // extend/oversize the plaintext for MAC compensation and 256 padding checks.
    val plaintextOversized = ByteArray(ciphertext.size + suite.macMessageBlockLength.coerceAtLeast(256))
    val ivLength = suite.recordIvLength
    val blockCipher = suite.threadLocalCipher ?: throw GeneralSecurityException("Local Cipher Suite not found!")
    blockCipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(ciphertext, 0, ivLength))
    val plaintextLength = blockCipher.doFinal(ciphertext, ivLength, ciphertext.size - ivLength, plaintextOversized)
    // fill up plaintext for MAC compensation
    System.arraycopy(FILLUP, 0, plaintextOversized, plaintextLength, suite.macMessageBlockLength)
    val macLength = suite.macLength
    // last byte contains padding length
    var paddingLength = plaintextOversized[plaintextLength - 1].toInt() and 0xff
    // -1 := padding length byte
    val fullLength = plaintextLength - macLength - 1
    val leftLength = fullLength - paddingLength
    var fragmentLength: Int
    if (leftLength < 0) {
      // padding length byte wrong
      fragmentLength = fullLength
      paddingLength = 0
    } else {
      fragmentLength = leftLength
    }
    if (!checkPadding(paddingLength, plaintextOversized, fragmentLength + macLength)) {
      fragmentLength = fullLength
      paddingLength = 0
    }
    // adjust fragment length
    val additionalIndex = additionalData.size - (16 / 8)
    additionalData[additionalIndex] = ((fragmentLength shl 8) and 0xff).toByte()
    additionalData[additionalIndex + 1] = (fragmentLength and 0xff).toByte()

    val md = suite.threadLocalMacMessageDigest ?: throw GeneralSecurityException("Local Message Digest not found!")
    md.reset()
    val localMac = suite.threadLocalMac ?: throw GeneralSecurityException("Local MAC not found!")
    val mac = getBlockCipherMac(localMac, macKey, additionalData, plaintextOversized, fragmentLength)

    // estimate additional MAC Hash compressions to decouple calculation
    // times from padding. The MAC Hash compressions are done in blocks,
    // appending the message length as extra data.
    val macMessageLengthBytes = suite.macMessageLengthBytes
    val macMessageBlockLength = suite.macMessageBlockLength
    // add all bytes passed to MAC
    val macBytes = additionalData.size + fragmentLength + macMessageLengthBytes
    // MAC blocks for all bytes including padding
    val macBlocks1 = (macBytes + paddingLength) / macMessageBlockLength
    // MAC blocks for all bytes without padding
    val macBlocks2 = macBytes / macMessageBlockLength
    val blocks = (macBlocks1 - macBlocks2)
    // calculate extra compression to compensate timing differences
    // caused by different padding
    // extra byte, to ensure, that the final compression is triggered
    md.update(plaintextOversized, fragmentLength, (blocks * macMessageBlockLength) + 1)
    md.reset()
    val macFromMessage = Arrays.copyOfRange(plaintextOversized, fragmentLength, fragmentLength + macLength)
    val ok = MessageDigest.isEqual(macFromMessage, mac)
    Bytes.clear(mac)
    Bytes.clear(macFromMessage)
    if (ok) {
      val payload = plaintextOversized.copyOf(fragmentLength)
      Bytes.clear(plaintextOversized)
      return payload
    } else {
      Bytes.clear(plaintextOversized)
      throw InvalidMacException()
    }
  }

  /**
   * Converts a given TLSCompressed. fragment to a TLSCiphertext.fragment structure as defined by [RFC 5246, section 6.2.3.2](https://tools.ietf.org/html/rfc5246#section-6.2.3.2).
   *
   * ```
   * struct {
   *  opaque IV[SecurityParameters.record_iv_length];
   *  block-ciphered struct {
   *    opaque content[TLSCompressed.length];
   *    opaque MAC[SecurityParameters.mac_length];
   *    uint8 padding[GenericBlockCipher.padding_length];
   *    uint8 padding_length;
   *  };
   * } GenericBlockCipher;
   * ```
   *
   * The particular cipher to use is determined from the negotiated cipher suite in the _current_ DTLS connection state.
   * @param suite used cipher suite
   * @param key encryption key
   * @param macKey mac key
   * @param additionalData additional data
   * @param payload message to encrypt
   * @return encrypted message including initial vector
   * @throws GeneralSecurityException if the plaintext could not be encrypted
   *
   */
  @Throws(GeneralSecurityException::class)
  fun encrypt(
    suite: CipherSuite,
    key: SecretKey,
    macKey: SecretKey,
    additionalData: ByteArray,
    payload: ByteArray,
  ): ByteArray {
    /*
     * see https://tools.ietf.org/html/rfc5246#section-6.2.3.2 for explanation
     */
    val plainMessage = DatagramWriter(payload.size + suite.macLength + suite.recordIvLength, true)
    plainMessage.writeBytes(payload)

    // add MAC
    val threadLocalMac = suite.threadLocalMac ?: throw GeneralSecurityException("Local MAC not found!")
    val mac = getBlockCipherMac(threadLocalMac, macKey, additionalData, payload, payload.size)
    plainMessage.writeBytes(mac)
    Bytes.clear(mac)

    // determine padding length
    val ciphertextLength = payload.size + suite.macLength + 1
    val blocksize = suite.recordIvLength
    val lastBlockBytes = ciphertextLength % blocksize
    val paddingLength = if (lastBlockBytes > 0) blocksize - lastBlockBytes else 0

    // create padding
    val padding = ByteArray(paddingLength + 1)
    Arrays.fill(padding, paddingLength.toByte())
    plainMessage.writeBytes(padding)
    Bytes.clear(padding)

    val blockCipher = suite.threadLocalCipher ?: throw GeneralSecurityException("Local Cipher Suite not found!")
    blockCipher.init(Cipher.ENCRYPT_MODE, key)
    val iv = blockCipher.iv
    val plaintext = plainMessage.toByteArray()
    plainMessage.close()

    val message = Arrays.copyOf(iv, iv.size + plaintext.size)
    blockCipher.doFinal(plaintext, 0, plaintext.size, message, iv.size)
    return message
  }

  /**
   * Calculates a MAC for use with CBC block ciphers as specified by [RFC 5246, section 6.2.3.2](https://tools.ietf.org/html/rfc5246#section-6.2.3.2).
   * @param hmac mac function
   * @param macKey mac key
   * @param additionalData additional data
   * @param content payload
   * @param length length of payload to be used
   * @return mac bytes
   * @throws InvalidKeyException if the mac keys doesn't fit the mac
   */
  @Throws(InvalidKeyException::class)
  fun getBlockCipherMac(
    hmac: Mac,
    macKey: SecretKey,
    additionalData: ByteArray,
    content: ByteArray,
    length: Int,
  ): ByteArray {
    hmac.init(macKey)
    hmac.update(additionalData)
    hmac.update(content, 0, length)
    val mac = hmac.doFinal()
    hmac.reset()
    return mac
  }

  /**
   * Check padding. The check is implemented using a "time constant" approach by always comparing 256 bytes.
   * @param padding padding to be checked
   * @param data data to be checked. Must contain at least 256 + 1 bytes from the offset on. The value of the last byte will be changed!
   * @param offset offset of the padding field.
   * @return `true`, if padding bytes in data from the offset on contains the value of the padding byte.
   * @throws IllegalArgumentException if the data array doesn't contain 257 bytes after the offset.
   */
  fun checkPadding(
    padding: Int,
    data: ByteArray,
    offset: Int,
  ): Boolean {
    require(data.size > offset + 256) { "data must contain 257 bytes from offset on!" }
    var result1 = 0
    var result2 = 0
    val pad = padding.toByte()
    for (index in 0..padding) {
      result1 = result1 or (pad.toInt() xor data[offset + index].toInt())
    }

    for (index in padding + 1 until 256) {
      result2 = result2 or (pad.toInt() xor data[offset + index].toInt())
    }
    // apply result2 at the "oversize" dummy data to ensure,
    // that the dummy loop is not skipped by optimization
    data[data.size - 1] = data[data.size - 1] xor result2.toByte()
    return result1 == 0
  }
}
