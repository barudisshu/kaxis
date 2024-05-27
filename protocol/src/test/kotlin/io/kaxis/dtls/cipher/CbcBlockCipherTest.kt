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
import kotlin.test.assertFalse

internal class CbcBlockCipherTest {
  companion object {
    @BeforeAll
    @JvmStatic
    fun init() {
      JceProvider.init()
    }

    const val SEQUENCE_NO: Long = 5
    const val TYPE_APPL_DATA: Int = 23
    const val EPOCH = 0

    val random = Random()

    // byte representation of a 128 bit AES symmetric key
    val aesKey = SecretKeySpec(Bytes.createBytes(random, 16), "AES")
    val aesKey256 = SecretKeySpec(Bytes.createBytes(random, 32), "AES")

    val aesMacKey = SecretKeySpec(Bytes.createBytes(random, 16), "AES")
    val aesMacKey256 = SecretKeySpec(Bytes.createBytes(random, 32), "AES")

    @JvmStatic
    fun parameters(): List<Array<Any>> {
      // Trying different message size to hit sharp corners in Coap-over-TCP spec
      val parameter = arrayListOf<Array<Any>>()
      parameter.add(arrayOf(0, 2))
      parameter.add(arrayOf(5, 2))
      parameter.add(arrayOf(13, 2))
      parameter.add(arrayOf(15, 13))
      parameter.add(arrayOf(16, 14))
      parameter.add(arrayOf(17, 15))
      parameter.add(arrayOf(31, 30))
      parameter.add(arrayOf(32, 31))
      parameter.add(arrayOf(33, 32))
      parameter.add(arrayOf(65805, 256))
      parameter.add(arrayOf(389805, 500))

      return parameter
    }
  }

  lateinit var additionalData: ByteArray
  lateinit var payloadData: ByteArray

  private fun adjustLength(
    data: ByteArray,
    len: Int,
  ): ByteArray {
    val adjusted = data.copyOf(len)
    if (data.size < len) {
      val temp = Bytes.createBytes(CcmBlockCipherTest.random, len - data.size)
      System.arraycopy(temp, 0, adjusted, data.size, temp.size)
    }
    return adjusted
  }

  fun provisioning(
    payloadLength: Int,
    aLength: Int,
  ) {
    // salt: 32bit client write init vector (can be any four bytes)
    val protocolVer = ProtocolVersion.VERSION_DTLS_1_2
    payloadData = Bytes.createBytes(random, payloadLength)

    // 64bit sequence number, consisting of 16bit epoch(0) + 48bit sequence number(5)
    val seqNum = byteArrayOf(0x00, EPOCH.toByte(), 0x00, 0x00, 0x00, 0x00, 0x00, SEQUENCE_NO.toByte())

    // additional data based on sequence number, type (APPLICATION_DATA) and protocol version
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
    val additionalIndex = additionalData.size - (16 / 8)
    additionalData[additionalIndex] = ((payloadLength shl 8) and 0xff).toByte()
    additionalData[additionalIndex + 1] = (payloadLength and 0xff).toByte()
  }

  @ParameterizedTest(name = "0{index}: payloadLength: ''{0}'', aLength: ''{1}''")
  @MethodSource("parameters")
  fun testAes128Sha256Cryption(
    payloadLength: Int,
    aLength: Int,
  ) {
    provisioning(payloadLength, aLength)

    val encryptedData =
      CbcBlockCipher.encrypt(
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        aesKey,
        aesMacKey,
        additionalData,
        payloadData,
      )
    val decryptedData =
      CbcBlockCipher.decrypt(
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        aesKey,
        aesMacKey,
        additionalData,
        encryptedData,
      )
    assertArrayEquals(payloadData, decryptedData)
  }

  @ParameterizedTest(name = "0{index}: payloadLength: ''{0}'', aLength: ''{1}''")
  @MethodSource("parameters")
  fun testAes256And128CryptionFails(
    payloadLength: Int,
    aLength: Int,
  ) {
    provisioning(payloadLength, aLength)
    assertTrue(JceProvider.hasStrongEncryption(), "requires strong encryption enabled")
    val encryptedData =
      CbcBlockCipher.encrypt(
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        aesKey256,
        aesMacKey256,
        additionalData,
        payloadData,
      )
    assertThrows<InvalidMacException> {
      CbcBlockCipher.decrypt(
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        aesKey,
        aesMacKey,
        additionalData,
        encryptedData,
      )
    }
  }

  @ParameterizedTest(name = "0{index}: payloadLength: ''{0}'', aLength: ''{1}''")
  @MethodSource("parameters")
  fun testAes256Sha384Cryption(
    payloadLength: Int,
    aLength: Int,
  ) {
    provisioning(payloadLength, aLength)
    val encryptedData =
      CbcBlockCipher.encrypt(
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        aesKey256,
        aesMacKey256,
        additionalData,
        payloadData,
      )
    val decryptedData =
      CbcBlockCipher.decrypt(
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        aesKey256,
        aesMacKey256,
        additionalData,
        encryptedData,
      )
    assertArrayEquals(payloadData, decryptedData)
  }

  @ParameterizedTest(name = "0{index}: payloadLength: ''{0}'', aLength: ''{1}''")
  @MethodSource("parameters")
  fun testAes256Cryption(
    payloadLength: Int,
    aLength: Int,
  ) {
    provisioning(payloadLength, aLength)
    val encryptedData =
      CbcBlockCipher.encrypt(
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        aesKey256,
        aesMacKey256,
        additionalData,
        payloadData,
      )
    val decryptedData =
      CbcBlockCipher.decrypt(
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        aesKey256,
        aesMacKey256,
        additionalData,
        encryptedData,
      )
    assertArrayEquals(payloadData, decryptedData)
  }

  @ParameterizedTest(name = "0{index}: payloadLength: ''{0}'', aLength: ''{1}''")
  @MethodSource("parameters")
  fun testDifferentCryption(
    payloadLength: Int,
    aLength: Int,
  ) {
    provisioning(payloadLength, aLength)
    val encryptedData =
      CbcBlockCipher.encrypt(
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        aesKey,
        aesMacKey,
        additionalData,
        payloadData,
      )
    encryptedData[0] = encryptedData[0] xor 0x55
    assertThrows<InvalidMacException> {
      CbcBlockCipher.decrypt(
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        aesKey,
        aesMacKey,
        additionalData,
        encryptedData,
      )
    }
  }

  @ParameterizedTest(name = "0{index}: payloadLength: ''{0}'', aLength: ''{1}''")
  @MethodSource("parameters")
  fun testDifferentAdditionalData(
    payloadLength: Int,
    aLength: Int,
  ) {
    provisioning(payloadLength, aLength)
    val encryptedData =
      CbcBlockCipher.encrypt(
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        aesKey,
        aesMacKey,
        additionalData,
        payloadData,
      )
    val additionData2 = additionalData.copyOf(additionalData.size + 1)
    additionData2[0] = additionData2[0] xor 0x55
    assertThrows<InvalidMacException> {
      CbcBlockCipher.decrypt(
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        aesKey,
        aesMacKey,
        additionData2,
        encryptedData,
      )
    }
  }

  @ParameterizedTest(name = "0{index}: payloadLength: ''{0}'', aLength: ''{1}''")
  @MethodSource("parameters")
  fun testDifferentKey(
    payloadLength: Int,
    aLength: Int,
  ) {
    provisioning(payloadLength, aLength)

    val encryptedData =
      CbcBlockCipher.encrypt(
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        aesKey,
        aesMacKey,
        additionalData,
        payloadData,
      )
    val aesKeyBytes = aesKey.encoded
    aesKeyBytes[0] = aesKeyBytes[0] xor 0x55
    assertThrows<InvalidMacException> {
      CbcBlockCipher.decrypt(
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        SecretKeySpec(aesKeyBytes, "AES"),
        aesMacKey,
        additionalData,
        encryptedData,
      )
    }
  }

  @ParameterizedTest(name = "0{index}: payloadLength: ''{0}'', aLength: ''{1}''")
  @MethodSource("parameters")
  fun testPaddingCheck(
    payloadLength: Int,
    aLength: Int,
  ) {
    provisioning(payloadLength, aLength)

    var padding = aLength
    while (padding > 256) {
      padding = padding ushr 1
    }
    val data = payloadData.copyOf(payloadLength + padding + 256)
    for (index in payloadLength..payloadLength + padding) {
      data[index] = padding.toByte()
    }
    assertTrue(CbcBlockCipher.checkPadding(padding, data, payloadLength))
    if (payloadLength > 0) {
      data[payloadLength - 1] = data[payloadLength - 1] xor 0x55
      assertTrue(CbcBlockCipher.checkPadding(padding, data, payloadLength))
    }
    data[payloadLength + padding + 1] = data[payloadLength + padding + 1] xor 0x55
    assertTrue(CbcBlockCipher.checkPadding(padding, data, payloadLength))
    var broken = data.copyOf()
    broken[payloadLength] = broken[payloadLength] xor 0x55
    assertFalse(CbcBlockCipher.checkPadding(padding, broken, payloadLength))
    broken = data.copyOf()
    broken[payloadLength + padding] = broken[payloadLength + padding] xor 0x55
    assertFalse(CbcBlockCipher.checkPadding(padding, broken, payloadLength))
  }

  @ParameterizedTest(name = "0{index}: payloadLength: ''{0}'', aLength: ''{1}''")
  @MethodSource("parameters")
  fun testPaddingException(
    payloadLength: Int,
    aLength: Int,
  ) {
    provisioning(payloadLength, aLength)

    assertThrows<IllegalArgumentException> { CbcBlockCipher.checkPadding(1, payloadData, payloadLength - 256) }
  }
}
