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

import io.kaxis.exception.InvalidMacException
import org.slf4j.LoggerFactory
import java.security.GeneralSecurityException
import java.security.NoSuchAlgorithmException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * A generic `Authenticated Encryption with Associated Data (AEAD，带有关联资料的认证加密, AE的变种)` block cipher mode.
 *
 * Usually cryptographic applications do not only require to have the data encrypted,
 * hence confidential, but also the data to be available only to authorized people.
 *
 * The reason behind this is that an attacker can intercept this information, and change it,
 * replacing part or all with other information encrypted in the same way so the recipient will not
 * understand the modification. In order to solve this problem, a `Message Authentication Code (MAC，信息识别码)`
 * is used, which provides the integrity of a message, and this is used often in combination with
 * encryption to provide both confidentiality and integrity.
 */
object AeadBlockCipher {
  private val LOGGER = LoggerFactory.getLogger(AeadBlockCipher::class.java)

  /**
   * Support java prior 1.7, aes-ccm is a non-java-vm transformation and
   * handled as special transformation.
   *
   * @see CCMBlockCipher
   *
   */
  @Deprecated("use $AES_CCM_NO_PADDING instead")
  val AES_CCM: String = "AES/CCM"

  /**
   * Support java prior 1.7, aes-ccm is a non-java-vm transformation and
   * handled as special transformation.
   *
   * @see CCMBlockCipher
   */
  const val AES_CCM_NO_PADDING: String = "AES/CCM/NoPadding"

  /**
   * Test, if transformation is "AES/CCM/???".
   * @param transformation transformation.
   * @return `true`, if transformation is "AES/CCM/???", `false`, otherwise.
   */
  fun isAesCcm(transformation: String): Boolean =
    AES_CCM_NO_PADDING.equals(transformation, true) || AES_CCM.equals(transformation, true)

  /**
   * Test, if cipher is supported.
   * @param transformation name of cipher
   * @param keyLength key length in bytes
   * @return `true`, if supported
   */
  fun isSupported(
    transformation: String,
    keyLength: Int,
  ): Boolean {
    var maxKeyLengthBits = 0
    try {
      maxKeyLengthBits = Cipher.getMaxAllowedKeyLength(transformation)
    } catch (ex: NoSuchAlgorithmException) {
      // NOSONAR
    }
    when (maxKeyLengthBits) {
      0 -> {
        LOGGER.debug("{} is not supported!", transformation)
      }

      Int.MAX_VALUE -> {
        LOGGER.debug("{} is not restricted!", transformation)
      }

      else -> {
        LOGGER.debug("{} is restricted to {} bits.", transformation, maxKeyLengthBits)
      }
    }
    return keyLength * Byte.SIZE_BITS <= maxKeyLengthBits
  }

  /**
   * Decrypt with AEAD cipher.
   *
   * ### Authenticated Decryption
   *
   * The authenticated decryption has as input parameters:
   *
   * - The Secret Key (`K`) used to encrypt the plain text
   * - A Nonce (`N`) unique within the same key (unless zero-length nonce)
   * - The Associated Data (`A`) that will be authenticated but not encrypted
   * - A Cipher text (`C`) which is the data to be decrypted and authenticated
   *
   * Whenever the result of the authenticated decryption is a plaintext (`P`) the
   * integrity of the associated parameters and of the plaintext/cipher text is assured
   * (assuming the AEAD algorithm is secure). If the decryption fails this means
   * that one or more parameters cannot be authenticated.
   *
   * @param cipherSuite the cipher suite
   * @param key the encryption key `K`
   * @param nonce the nonce `N`
   * @param associatedData the additional authenticated data `A`
   * @param crypted the encrypted and authenticated message `C`
   * @param cryptedOffset offset within crypted
   * @param cryptedLength length within crypted
   * @throws GeneralSecurityException if the message could not be de-crypted, e.g. because the ciphertext's block size is not correct
   * @throws InvalidMacException if the message could not be authenticated
   */
  @Throws(GeneralSecurityException::class)
  fun decrypt(
    cipherSuite: CipherSuite,
    key: SecretKey,
    nonce: ByteArray,
    associatedData: ByteArray,
    crypted: ByteArray,
    cryptedOffset: Int,
    cryptedLength: Int,
  ): ByteArray =
    if (isAesCcm(cipherSuite.transformation)) {
      CcmBlockCipher.decrypt(
        key,
        nonce,
        associatedData,
        crypted,
        cryptedOffset,
        cryptedLength,
        cipherSuite.macLength,
      )
    } else {
      jreDecrypt(cipherSuite, key, nonce, associatedData, crypted, cryptedOffset, cryptedLength)
    }

  /**
   * Encrypt with AEAD cipher.
   *
   * ### Authenticated Encryption
   *
   * In order to perform encryption with the possibility to verify its integrity, there are four input
   * parameters needed:
   *
   * - The Secret Key (`K`) used to encrypt the plain text
   * - A Nonce (`N`) unique within the same key (unless zero-length nonce)
   * - The Associated Data (`A`) that will be authenticated but not encrypted
   * - A Plaintext `P` which is the data to be encrypted and authenticated
   *
   * These parameters will produce a cipher text `C` containing the encrypted data
   * and a way to ensure its integrity.
   *
   * @param cipherSuite the cipher suite
   * @param key the encryption key `K`
   * @param nonce the nonce `N`
   * @param associatedData the additional authenticated data `A`
   * @param plaintext the message to authenticate and encrypt
   * @return the encrypted and authenticated message.
   * @throws GeneralSecurityException if the data could not be encrypted, e.g. because the JVM does not support the AES cipher algorithm.
   */
  @Throws(GeneralSecurityException::class)
  fun encrypt(
    cipherSuite: CipherSuite,
    key: SecretKey,
    nonce: ByteArray,
    associatedData: ByteArray,
    plaintext: ByteArray,
  ): ByteArray =
    if (isAesCcm(cipherSuite.transformation)) {
      CcmBlockCipher.encrypt(cipherSuite.recordIvLength, key, nonce, associatedData, plaintext, cipherSuite.macLength)
    } else {
      jreEncrypt(cipherSuite.recordIvLength, cipherSuite, key, nonce, associatedData, plaintext)
    }

  /**
   * Decrypt with jre AEAD cipher.
   * @param suite the cipher suite
   * @param key the encryption key `K`
   * @param nonce the nonce `N`
   * @param associatedData the additional authenticated data `A`
   * @param crypted the encrypted and authenticated message `C`
   * @param cryptedOffset offset within crypted
   * @param cryptedLength length within crypted
   * @return the decrypted message
   * @throws GeneralSecurityException if the message could not be de-crypted, e.g. because the ciphertext's block size is not correct
   * @throws InvalidMacException if the message could not be authenticated
   */
  @Throws(GeneralSecurityException::class)
  private fun jreDecrypt(
    suite: CipherSuite,
    key: SecretKey,
    nonce: ByteArray,
    associatedData: ByteArray,
    crypted: ByteArray,
    cryptedOffset: Int,
    cryptedLength: Int,
  ): ByteArray {
    val cipher = suite.threadLocalCipher ?: throw GeneralSecurityException("Local cipher suite not found!")
    val parameterSpec = GCMParameterSpec(suite.macLength * 8, nonce)
    cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec)
    cipher.updateAAD(associatedData)
    return try {
      cipher.doFinal(crypted, cryptedOffset, cryptedLength)
    } catch (ex: AEADBadTagException) {
      throw InvalidMacException(ex.message)
    }
  }

  /**
   * Encrypt with jre AEAD cipher.
   * @param outputOffset offset of the encrypted message within the result byte array. Leaves space for the explicit nonce.
   * @param suite the cipher suite
   * @param key the encryption key `K`
   * @param nonce the nonce `N`
   * @param associatedData the additional authenticated data `A`
   * @param message the message to authenticate and encrypt.
   * @return th encrypted and authenticated message.
   * @throws GeneralSecurityException if the data could not be encrypted, e.g. because the JVM does not support the AES cipher algorithm
   */
  @Throws(GeneralSecurityException::class)
  private fun jreEncrypt(
    outputOffset: Int,
    suite: CipherSuite,
    key: SecretKey,
    nonce: ByteArray,
    associatedData: ByteArray,
    message: ByteArray,
  ): ByteArray {
    val cipher = suite.threadLocalCipher ?: throw GeneralSecurityException("Local cipher suite not found!")
    val parameterSpec = GCMParameterSpec(suite.macLength * 8, nonce)
    cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec)
    cipher.updateAAD(associatedData)
    val length = cipher.getOutputSize(message.size)
    val result = ByteArray(length + outputOffset)
    cipher.doFinal(message, 0, message.size, result, outputOffset)
    return result
  }
}
