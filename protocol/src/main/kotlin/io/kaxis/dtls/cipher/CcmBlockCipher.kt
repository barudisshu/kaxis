/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.cipher

import io.kaxis.exception.InvalidMacException
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.ShortBufferException
import kotlin.experimental.xor

/**
 * A generic authenticated encryption block cipher mode which uses the 128-bit block cipher AES. See
 * [RFC 3610](https://tools.ietf.org/html/rfc3610) for details.
 *
 * CCM(Counter with CBC-MAC) is only defined for use with 128-bit block ciphers, such as AES.
 */
@Suppress("ktlint:standard:property-naming")
object CcmBlockCipher {
  /**
   * The underlying block cipher.
   *
   * **Note**: code scanners seems to be limited in analyzing code. Therefore, these scanners may report the use of
   * "AES/ECB" as finding. This implementation uses the basic form of AES ciphers (AES/ECB) to build AES/CCM
   * for older JREs. For more details, see [Wikipedia, Block cipher mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation).
   */
  private const val CIPHER_NAME = "AES/ECB/NoPadding"
  private val CIPHER = ThreadLocalCipher(CIPHER_NAME)

  private abstract class Block {
    val blockSize: Int
    val block: ByteArray

    constructor(blockSize: Int) {
      this.blockSize = blockSize
      this.block = ByteArray(blockSize)
    }

    /**
     * Set integer at the end of the block. Lowest byte at the end.
     *
     * ```java
     * block[end] = number & 0xff
     * block[end -1] = (number >>= 8) & 0xff
     * block[end -2] = (number >>= 8) & 0xff
     * block[offset] = (number >>= 8) & 0xff
     * ```
     *
     * Return remaining bytes in number.
     *
     * ```java
     * blockSize = 16
     * number = 0x20103
     * left = updateBlock(14, number) // write number to two bytes
     * left == 2 // highest third byte 0x2 will be left
     * ```
     *
     * @param offset offset at which the number will be written, right padded with 0
     * @param number number to write
     * @return left bytes of the number, if number is too large, 0. if the complete number could be set.
     */
    fun setIntAtEnd(
      offset: Int,
      number: Int,
    ): Int {
      var backOffset = blockSize
      var num = number
      while (backOffset > offset) {
        block[--backOffset] = number.toByte()
        num = num ushr 8
      }
      return num
    }
  }

  /**
   * With this section it has been explaining the last part of the main cipher
   * suite used in this document, that corresponds to the following string:
   *
   * ```
   * TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
   * ```
   *
   * where:
   *
   * - `TLS` means that this is a TLS cipher (DTLS uses the same ciphers since the two protocols are very similar)
   * - `ECDHE` is Ephemeral Elliptic Curve Diffie Hellman
   * - `ECDSA` stands for Elliptic Curves Digital Signature Algorithm
   * - `AES` is the Advanced Encryption Standard
   * - `CCM_8` stands for Counter mode with CBC-MAC with 8 bytes of associated data
   */
  private class BlockCipher : Block {
    private val cipher: Cipher
    private val xblock: ByteArray
    private val nonceL: Int

    constructor(cipher: Cipher, nonce: ByteArray) : super(cipher.blockSize) {
      this.cipher = cipher
      this.nonceL = nonce.size
      val L = blockSize - 1 - nonceL
      require(L in 2..8) {
        "Nonce length $nonceL invalid for block size $blockSize (valid length [${blockSize - 9}-${blockSize - 3}])"
      }
      xblock = ByteArray(blockSize)
      // Octet Number Contents
      // ------------ ---------
      // 0 flags
      // 1 ... 15-L Nonce N
      // 16-L ... 15 Counter i

      // write the first byte: Flags
      block[0] = (L - 1).toByte()
      // the Nonce N
      System.arraycopy(nonce, 0, block, 1, nonceL)
    }

    @Throws(ShortBufferException::class)
    fun updateBlock(index: Int): ByteArray {
      // writer the Counter 1 (L bytes)
      val idx = setIntAtEnd(nonceL + 1, index)
      require(idx == 0) { "Index $idx too large for nonce $nonceL and block size $blockSize bytes." }
      cipher.update(block, 0, blockSize, xblock)
      return xblock
    }
  }

  private class MacCipher : Block {
    private val cipher: Cipher
    val mac: ByteArray

    @Throws(ShortBufferException::class)
    constructor(cipher: Cipher, nonce: ByteArray, a: ByteArray, m: ByteArray, numAuthenticationBytes: Int) : super(
      cipher.blockSize,
    ) {
      this.cipher = cipher
      val lengthM = m.size
      val lengthA = a.size
      val nonceL = nonce.size
      val L = blockSize - 1 - nonceL
      require(L in 2..8) {
        "Nonce length $nonceL invalid for block size $blockSize (valid length [${blockSize - 9}-${blockSize - 3}])"
      }

      // build first block B_0

      // Octet Number Contents
      // ------------ ---------
      // 0 Flags
      // 1 ... 15-L Nonce N
      // 16-L ... 15 l(m)
      var adata = 0
      // the Adata bit is set to zero if l(a)=0, and set to one if l(a)>0
      if (lengthA > 0) {
        adata = 1
      }
      // M' field is set to (M-2)/2
      val mPrime = (numAuthenticationBytes - 2) / 2
      // L' = L-1 (the zero value is reserved)
      val lPrime = L - 1

      // Bit Number Contents
      // ---------- ----------------------
      // 7 Reserved (always zero)
      // 6 Adata
      // 5 ... 3 M'
      // 2 ... 0 L'

      // Flags = 64*Adata + 8*M' + L'
      block[0] = (64 * adata + 8 * mPrime + lPrime).toByte()

      // 1 ... 15-L Nonce N
      System.arraycopy(nonce, 0, block, 1, nonceL)

      // writer the length (L bytes)
      val lm = setIntAtEnd(nonceL + 1, lengthM)
      require(lm == 0) { "Length $lengthM too large for nonce $nonceL and block size $blockSize bytes." }

      cipher.update(block, 0, blockSize, block)

      // if l(a)>0 (as indicated by the Adata field), then one or more blocks
      // of authentication data are added.
      if (lengthA > 0) {
        // First two octets Followed by Comment
        // ---------------------------------------
        // 0x0000 Nothing Reserved
        // 0x0001 ... 0xFEFF Nothing For 0 < l(a) < (2^16 - 2^8)
        // 0xFF00 ...0xFFFD Nothing Reserved
        // 0xFFFE 4 octets of l(a) For (2^16 - 2^8) <= l(a) < 2^32
        // 0xFFFF 8 octets of l(a) For 2^32 <= l(a) < 2^64

        // 2^16 - 2^8
        val first = 65280
        val offset =
          if (lengthA < first) {
            // 2 bytes (0x0001 ... 0xFEFF)
            xorInt(0, 2, lengthA)
            2
          } else {
            // 2 bytes (0xFFFE) + 4 octets of l(a)
            xorInt(0, 2, 0xfffe)
            xorInt(2, 6, lengthA)
            6
          }
        update(a, offset)
      }
      update(m, 0)
      mac = block.copyOf(numAuthenticationBytes)
    }

    @Throws(ShortBufferException::class)
    private fun update(
      data: ByteArray,
      initialBlockOffset: Int,
    ) {
      val length = data.size
      var init = initialBlockOffset
      var i = 0
      while (i < length) {
        var blockEnd = i + blockSize - init
        if (blockEnd > length) {
          blockEnd = length
        }
        var j = init
        while (i < blockEnd) {
          block[j] = (block[j].toInt() xor data[i].toInt()).toByte()
          ++i
          ++j
        }
        init = 0
        cipher.update(block, 0, blockSize, block)
      }
    }

    fun xorInt(
      offset: Int,
      end: Int,
      number: Int,
    ) {
      var e = end
      var n = number
      while (e > offset) {
        block[--e] = (block[--e].toInt() xor n).toByte()
        n = n ushr 8
      }
    }
  }

  // Static methods /////////////////////////////////////////////////////////

  /**
   * Checks, if AES/CCM cipher is supported. Checks, if the AES/ECB cipher is supported for this JRE in order to
   * build a AES/CCM cipher based on that.
   * @return `true`, if AES/CCM is supported, `false`, if not.
   */
  fun isSupported(): Boolean = CIPHER.isSupported

  /**
   * Returns the maximum key length of AES/CCM according to the installed JCE jurisdiction policy files.
   * @return the maximum key length in bits or [Int.MAX_VALUE]
   * @throws NoSuchAlgorithmException if "AES/ECB" is not supported.
   */
  @Throws(NoSuchAlgorithmException::class)
  fun getMaxAllowedKeyLength(): Int {
    return Cipher.getMaxAllowedKeyLength(CIPHER_NAME)
  }

  /**
   * See [RFC 3610](https://tools.ietf.org/html/rfc3610#section-2.5) for details.
   * @param key the encryption key `K`
   * @param nonce the nonce `N`
   * @param associatedData the associated authenticated data `A`
   * @param crypted the encrypted and authenticated message `C`
   * @param numAuthenticationBytes Number of octets in authentication field
   * @return the decrypted message
   * @throws GeneralSecurityException if the message could not be de-crypted, e.g. because the
   * ciphertext's block size is not correct
   * @throws InvalidMacException if the message could not be authenticated
   */
  @Throws(GeneralSecurityException::class)
  fun decrypt(
    key: SecretKey,
    nonce: ByteArray,
    associatedData: ByteArray,
    crypted: ByteArray,
    numAuthenticationBytes: Int,
  ): ByteArray {
    return decrypt(key, nonce, associatedData, crypted, 0, crypted.size, numAuthenticationBytes)
  }

  /**
   * See [RFC 3610](https://tools.ietf.org/html/rfc3610#section-2.5) for details.
   *
   * **Authenticated Decryption** The authenticated decryption has as input parameters:
   *
   * - The Secret Key (K) used to encrypt the plain text
   * - A Nonce (N) unique within the same key (unless zero-length nonce)
   * - The Associated Data (A) that will be authenticated but not encrypted
   * - A Cipher text (C) which is the data to be decrypted and authenticated
   *
   * Whenever the result of the authenticated decryption is a plaintext (P) the
   * integrity of the associated parameters and of the plaintext/cipher text is assured
   * (assuming the AEAD algorithm is secure). If the decryption fails this means that
   * one or more parameters cannot be authenticated.
   *
   * @param key the encryption key `K`
   * @param nonce the nonce `N`
   * @param associatedData the associated authenticated data `A`
   * @param crypted the encrypted and authenticated message `C`
   * @param cryptedOffset offset within crypted
   * @param cryptedLength length within crypted
   * @param numAuthenticationBytes Number of octets in authentication field.
   * @return the decrypted message
   * @throws GeneralSecurityException if the message could not be de-crypted, e.g. because the
   * ciphertext's block size is not correct
   * @throws InvalidMacException if the message could not be authenticated
   */
  @Throws(GeneralSecurityException::class)
  fun decrypt(
    key: SecretKey,
    nonce: ByteArray,
    associatedData: ByteArray,
    crypted: ByteArray,
    cryptedOffset: Int,
    cryptedLength: Int,
    numAuthenticationBytes: Int,
  ): ByteArray {
    // instantiate the underlying block cipher
    val cipher = CIPHER.current() ?: throw GeneralSecurityException("Local AES/ECB Cipher Suite not found!")
    cipher.init(Cipher.ENCRYPT_MODE, key)

    val lengthM = cryptedLength - numAuthenticationBytes
    val blockSize = cipher.blockSize

    // decrypted data without MAC
    val decrypted = ByteArray(lengthM)
    // separate MAC
    val T = ByteArray(numAuthenticationBytes)

    val blockCipher = BlockCipher(cipher, nonce)
    // block 0 for MAC
    var blockNo = 0
    var block = blockCipher.updateBlock(blockNo++)
    val tOffset = cryptedOffset + lengthM
    for (i in 0..<numAuthenticationBytes) {
      T[i] = (crypted[tOffset + i] xor block[i])
    }

    var i = 0
    while (i < lengthM) {
      block = blockCipher.updateBlock(blockNo++)
      var blockEnd = i + blockSize
      if (blockEnd > lengthM) {
        blockEnd = lengthM
      }
      var j = 0
      while (i < blockEnd) {
        decrypted[i] = (crypted[cryptedOffset + i] xor block[j])
        ++i
        ++j
      }
    }

    /*
     * The message and additional authentication data is then used to
     * recompute the CBC-MAC value and check T.
     */
    val macCipher = MacCipher(cipher, nonce, associatedData, decrypted, numAuthenticationBytes)
    val mac = macCipher.mac

    /*
     * If the T value is not correct, the receiver MUST NOT reveal any
     * information except for the fact that T is incorrect. The receiver
     * MUST NOT reveal the decrypted message, the value T, or any other information.
     */
    return if (MessageDigest.isEqual(T, mac)) {
      decrypted
    } else {
      throw InvalidMacException(mac, T)
    }
  }

  /**
   * See [RFC 3610](https://tools.ietf.org/html/rfc3610#section-2.2) for details.
   * @param key the encryption key `K`
   * @param nonce the nonce `N`
   * @param associatedData the associated authenticated data `A`
   * @param message the message to authenticate and encrypt
   * @param numAuthenticationBytes Number of octets in authentication field
   * @return the encrypted and authenticated message
   * @throws GeneralSecurityException if the data could not be encrypted, e.g. because the JVM does not support the AES cipher algorithm.
   */
  @Throws(GeneralSecurityException::class)
  fun encrypt(
    key: SecretKey,
    nonce: ByteArray,
    associatedData: ByteArray,
    message: ByteArray,
    numAuthenticationBytes: Int,
  ): ByteArray {
    return encrypt(0, key, nonce, associatedData, message, numAuthenticationBytes)
  }

  /**
   * See [RFC 3610](https://tools.ietf.org/html/rfc3610#section-2.2) for details.
   *
   * **Authenticated Encryption** In order to perform encryption with the possibility to verify its integrity, there are
   * four input parameters needed:
   *
   * - The Secret Key (K) used to encrypt the plain text
   * - A Nonce (N) unique within the same key (unless zero-length nonce)
   * - The Associated Data (A) that will be authenticated but not encrypted
   * - A Plaintext P which is the data to be encrypted and authenticated
   *
   * These parameters will produce a cipher text C containing the encrypted data and a way to ensure its integrity.
   *
   * @param outputOffset offset of the encrypted message within the resulting byte array. Leaves space for the explicit nonce.
   * @param key the encryption key `K`
   * @param nonce the nonce `N`
   * @param associatedData the associated authenticated data `A`
   * @param message the message to authenticate and encrypt
   * @param numAuthenticationBytes Number of octets in authentication field
   * @return the encrypted and authenticated message
   * @throws GeneralSecurityException if the data could not be encrypted, e.g. because the JVM does not support the AES cipher algorithm
   */
  @Throws(GeneralSecurityException::class)
  fun encrypt(
    outputOffset: Int,
    key: SecretKey,
    nonce: ByteArray,
    associatedData: ByteArray,
    message: ByteArray,
    numAuthenticationBytes: Int,
  ): ByteArray {
    // instantiate the cipher
    val cipher = CIPHER.current() ?: throw GeneralSecurityException("Local AES/ECB Cipher Suite not found!")
    cipher.init(Cipher.ENCRYPT_MODE, key)
    val blockSize = cipher.blockSize
    val lengthM = message.size

    /*
     * First, authentication: https://tools.ietf.org/html/rfc3610#section-2.2
     */

    // compute the authentication field T
    val macCipher = MacCipher(cipher, nonce, associatedData, message, numAuthenticationBytes)
    val mac = macCipher.mac

    /*
     * Second, encryption https://tools.ietf.org/html/rfc3610#section-2.3
     */

    // encrypted data with MAC
    val encrypted = ByteArray(outputOffset + lengthM + numAuthenticationBytes)
    val blockCipher = BlockCipher(cipher, nonce)
    // block 0 for MAC
    var blockNo = 0
    var block = blockCipher.updateBlock(blockNo++)
    val tOffset = outputOffset + lengthM
    for (i in 0 until numAuthenticationBytes) {
      encrypted[i + tOffset] = (mac[i] xor block[i])
    }
    var i = 0
    while (i < lengthM) {
      block = blockCipher.updateBlock(blockNo++)
      var blockEnd = i + blockSize
      if (blockEnd > lengthM) {
        blockEnd = lengthM
      }
      var j = 0
      while (i < blockEnd) {
        encrypted[i + outputOffset] = (message[i] xor block[j])
        ++i
        ++j
      }
    }
    return encrypted
  }
}
