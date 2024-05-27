/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.cipher

import io.kaxis.Bytes
import io.kaxis.JceProvider
import io.kaxis.dtls.ProtocolVersion
import io.kaxis.exception.InvalidMacException
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.util.*
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.xor

internal class CcmBlockCipherTest {
  companion object {
    @BeforeAll
    @JvmStatic
    fun init() {
      JceProvider.init()
    }

    const val SEQUENCE_NO: Long = 5
    const val TYPE_APPL_DATA: Int = 23
    const val EPOCH = 0

    // byte representation of a 128 bits AES symmetric key
    val aesKeyBytes =
      byteArrayOf(
        0xC9.toByte(),
        0x0E,
        0x6A,
        0xA2.toByte(),
        0xEF.toByte(),
        0x60,
        0x34,
        0x96.toByte(),
        0x90.toByte(),
        0x54,
        0xC4.toByte(),
        0x96.toByte(),
        0x65,
        0xBA.toByte(),
        0x03,
        0x9E.toByte(),
      )
    val aesKey = SecretKeySpec(aesKeyBytes, "AES")
    val aesKey256 = SecretKeySpec(Bytes.concatenate(aesKeyBytes, aesKeyBytes), "AES")

    @JvmStatic
    fun parameters(): List<Array<Any>> {
      // Trying different message size to hit sharp corners in Coap-over-TCP spec
      val parameter = arrayListOf<Array<Any>>()
      parameter.add(arrayOf(0, 0, 7))
      parameter.add(arrayOf(5, 0, 7))
      parameter.add(arrayOf(13, 1, 7))
      parameter.add(arrayOf(15, 13, 8))
      parameter.add(arrayOf(16, 14, 8))
      parameter.add(arrayOf(17, 15, 12))
      parameter.add(arrayOf(31, 30, 13))
      parameter.add(arrayOf(32, 31, 12))
      parameter.add(arrayOf(33, 32, 12))
      parameter.add(arrayOf(65805, 256, 8))
      parameter.add(arrayOf(389805, 500, 8))

      return parameter
    }

    val random = Random()
  }

  lateinit var additionalData: ByteArray
  lateinit var nonce: ByteArray
  lateinit var payloadData: ByteArray

  private fun adjustLength(
    data: ByteArray,
    len: Int,
  ): ByteArray {
    val adjusted = data.copyOf(len)
    if (data.size < len) {
      val temp = Bytes.createBytes(random, len - data.size)
      System.arraycopy(temp, 0, adjusted, data.size, temp.size)
    }
    return adjusted
  }

  fun provisioning(
    payloadLength: Int,
    aLength: Int,
    nonceLength: Int,
  ) {
    // salt: 32bit client write init vector (can be any four bytes)
    val clientIv = byteArrayOf(0x55, 0x23, 0x2F, 0xA3.toByte())
    val protocolVer = ProtocolVersion.VERSION_DTLS_1_2
    payloadData = Bytes.createBytes(random, payloadLength)

    // 64bit sequence number, consisting of 16bit epoch(0) + 48 bit sequence number (5)
    val seqNum = byteArrayOf(0x00, EPOCH.toByte(), 0x00, 0x00, 0x00, 0x00, 0x00, SEQUENCE_NO.toByte())

    // additional data based on sequence number, type (APPLICATION DATA) and protocol version
    additionalData =
      byteArrayOf(
        TYPE_APPL_DATA.toByte(),
        protocolVer.major.toByte(),
        protocolVer.minor.toByte(),
        0,
        payloadLength.toByte(),
      )
    additionalData = Bytes.concatenate(seqNum, additionalData)
    additionalData = adjustLength(additionalData, aLength)
    // "explicit" part of nonce, intentionally different from seq_num which MAY be used as the explicit nonce
    // but does not need to be used (at least that's my interpretation of the specs)
    val explicitNonce = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
    // nonce used for encryption, "implicit" part + "explicit" part
    nonce = Bytes.concatenate(clientIv, explicitNonce)
    nonce = adjustLength(nonce, nonceLength)
  }

  @ParameterizedTest(name = "0{index}: payloadLength: ''{0}'', aLength: ''{1}'', nonceLength: ''{2}''")
  @MethodSource("parameters")
  fun testAES128CcmCryption(
    payloadLength: Int,
    aLength: Int,
    nonceLength: Int,
  ) {
    provisioning(payloadLength, aLength, nonceLength)

    val encryptedData = CcmBlockCipher.encrypt(aesKey, nonce, additionalData, payloadData, 16)
    val decryptedData = CcmBlockCipher.decrypt(aesKey, nonce, additionalData, encryptedData, 16)
    assertArrayEquals(payloadData, decryptedData)
  }

  /**
   * Test, if using a 256 key fore encryption and 128 key for decryption fails with invalid MAC. Check AES 256
   * with 1.8.0_144 requires strong encryption enable [1.8.0_171](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html) seems to work out of box.
   */
  @ParameterizedTest(name = "0{index}: payloadLength: ''{0}'', aLength: ''{1}'', nonceLength: ''{2}''")
  @MethodSource("parameters")
  fun testAES256And128CryptionFails(
    payloadLength: Int,
    aLength: Int,
    nonceLength: Int,
  ) {
    provisioning(payloadLength, aLength, nonceLength)

    assertTrue(JceProvider.hasStrongEncryption(), "requires strong encryption enabled")
    val encryptedData = CcmBlockCipher.encrypt(aesKey256, nonce, additionalData, payloadData, 8)
    assertThrows<InvalidMacException> { CcmBlockCipher.decrypt(aesKey, nonce, additionalData, encryptedData, 8) }
  }

  /**
   * Check AES 256
   * with 1.8.0_144 requires strong encryption enable [1.8.0_171](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html) seems to work out of box.
   */
  @ParameterizedTest(name = "0{index}: payloadLength: ''{0}'', aLength: ''{1}'', nonceLength: ''{2}''")
  @MethodSource("parameters")
  fun testAES256Ccm8Cryption(
    payloadLength: Int,
    aLength: Int,
    nonceLength: Int,
  ) {
    provisioning(payloadLength, aLength, nonceLength)

    assertTrue(JceProvider.hasStrongEncryption(), "requires strong encryption enabled")
    val encryptedData = CcmBlockCipher.encrypt(aesKey256, nonce, additionalData, payloadData, 8)
    val decryptedData = CcmBlockCipher.decrypt(aesKey256, nonce, additionalData, encryptedData, 8)
    assertArrayEquals(payloadData, decryptedData)
  }

  @ParameterizedTest(name = "0{index}: payloadLength: ''{0}'', aLength: ''{1}'', nonceLength: ''{2}''")
  @MethodSource("parameters")
  fun testAES256CcmCryption(
    payloadLength: Int,
    aLength: Int,
    nonceLength: Int,
  ) {
    provisioning(payloadLength, aLength, nonceLength)

    assertTrue(JceProvider.hasStrongEncryption(), "requires strong encryption enabled")
    val encryptedData = CcmBlockCipher.encrypt(aesKey256, nonce, additionalData, payloadData, 16)
    val decryptedData = CcmBlockCipher.decrypt(aesKey256, nonce, additionalData, encryptedData, 16)
    assertArrayEquals(payloadData, decryptedData)
  }

  @ParameterizedTest(name = "0{index}: payloadLength: ''{0}'', aLength: ''{1}'', nonceLength: ''{2}''")
  @MethodSource("parameters")
  fun testFastFastCryption(
    payloadLength: Int,
    aLength: Int,
    nonceLength: Int,
  ) {
    provisioning(payloadLength, aLength, nonceLength)

    assertTrue(JceProvider.hasStrongEncryption(), "requires strong encryption enabled")
    val encryptedData = CcmBlockCipher.encrypt(aesKey, nonce, additionalData, payloadData, 8)
    val decryptedData = CcmBlockCipher.decrypt(aesKey, nonce, additionalData, encryptedData, 8)
    assertArrayEquals(payloadData, decryptedData)
  }

  @ParameterizedTest(name = "0{index}: payloadLength: ''{0}'', aLength: ''{1}'', nonceLength: ''{2}''")
  @MethodSource("parameters")
  fun testDifferentNonce(
    payloadLength: Int,
    aLength: Int,
    nonceLength: Int,
  ) {
    provisioning(payloadLength, aLength, nonceLength)

    val encryptedData = CcmBlockCipher.encrypt(aesKey, nonce, additionalData, payloadData, 8)
    val nonce2 = nonce.copyOf(nonce.size)
    nonce2[0] = nonce2[0] xor 0x55
    assertThrows<InvalidMacException> { CcmBlockCipher.decrypt(aesKey, nonce2, additionalData, encryptedData, 8) }
  }

  @ParameterizedTest(name = "0{index}: payloadLength: ''{0}'', aLength: ''{1}'', nonceLength: ''{2}''")
  @MethodSource("parameters")
  fun testDifferentAdditionalData(
    payloadLength: Int,
    aLength: Int,
    nonceLength: Int,
  ) {
    provisioning(payloadLength, aLength, nonceLength)

    val encryptedData = CcmBlockCipher.encrypt(aesKey, nonce, additionalData, payloadData, 8)
    val additionalData2 = additionalData.copyOf(additionalData.size + 1)
    additionalData2[0] = additionalData2[0] xor 0x55
    assertThrows<InvalidMacException> { CcmBlockCipher.decrypt(aesKey, nonce, additionalData2, encryptedData, 8) }
  }

  @ParameterizedTest(name = "0{index}: payloadLength: ''{0}'', aLength: ''{1}'', nonceLength: ''{2}''")
  @MethodSource("parameters")
  fun testDifferentKey(
    payloadLength: Int,
    aLength: Int,
    nonceLength: Int,
  ) {
    provisioning(payloadLength, aLength, nonceLength)

    val encryptedData = CcmBlockCipher.encrypt(aesKey, nonce, additionalData, payloadData, 8)
    val aesKey2 = aesKeyBytes.copyOf(aesKeyBytes.size)
    aesKey2[0] = aesKey2[0] xor 0x55
    assertThrows<InvalidMacException> {
      CcmBlockCipher.decrypt(
        SecretKeySpec(aesKey2, "AES"),
        nonce,
        additionalData,
        encryptedData,
        8,
      )
    }
  }

  @ParameterizedTest(name = "0{index}: payloadLength: ''{0}'', aLength: ''{1}'', nonceLength: ''{2}''")
  @MethodSource("parameters")
  fun testTooShortNonce(
    payloadLength: Int,
    aLength: Int,
    nonceLength: Int,
  ) {
    provisioning(payloadLength, aLength, nonceLength)

    val nonce2 = nonce.copyOf(6)
    assertThrows<IllegalArgumentException> { CcmBlockCipher.encrypt(aesKey, nonce2, additionalData, payloadData, 8) }
  }

  @ParameterizedTest(name = "0{index}: payloadLength: ''{0}'', aLength: ''{1}'', nonceLength: ''{2}''")
  @MethodSource("parameters")
  fun testTooLongNonce(
    payloadLength: Int,
    aLength: Int,
    nonceLength: Int,
  ) {
    provisioning(payloadLength, aLength, nonceLength)

    val nonce2 = adjustLength(nonce, 14)
    assertThrows<IllegalArgumentException> { CcmBlockCipher.encrypt(aesKey, nonce2, additionalData, payloadData, 8) }
  }
}
