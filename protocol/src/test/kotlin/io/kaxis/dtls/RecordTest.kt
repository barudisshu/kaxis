/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls

import io.kaxis.Bytes
import io.kaxis.dtls.cipher.CcmBlockCipher
import io.kaxis.util.ClockUtil
import io.kaxis.util.DatagramReader
import io.kaxis.util.Utility
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.file.Files
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import kotlin.io.path.toPath
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

internal class RecordTest {
  companion object {
    const val SEQUENCE_NO: Long = 5
    const val TYPE_APPL_DATA = 23
    const val EPOCH = 1

    // byte representation of a 128 bit AES symmetric key
    val aesKey =
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
  }

  lateinit var key: SecretKey
  lateinit var payloadData: ByteArray
  val payloadLength = 50

  // salt: 32bit client write init vector (can be any four bytes)
  val clientIv = byteArrayOf(0x55, 0x23, 0x2F, 0xA3.toByte())
  lateinit var protocolVer: ProtocolVersion

  @BeforeEach
  fun setUp() {
    protocolVer = ProtocolVersion.VERSION_DTLS_1_2
    key = SecretKeySpec(aesKey, "AES")
    payloadData = ByteArray(payloadLength)
    for (i in 0..<payloadLength) {
      payloadData[i] = 0x34
    }
  }

  @Test
  fun testDecryptAEADUsesExplicitNonceFromGenericAEADCipherStruct() {
    val fragment = newGenericAEADCipherFragment()
    val record =
      Record(
        ContentType.APPLICATION_DATA,
        protocolVer,
        EPOCH,
        SEQUENCE_NO,
        null,
        fragment,
        ClockUtil.nanoRealtime(),
        false,
      )

    assertNotNull(record)
  }

  @Test
  fun testFromReaderClientHello() {
    val records = loadPackageData("cap/00_client_hello.txt")
    assertEquals(1, records.size)
    val record = records.first()
    assertTrue(record.isNewClientHello)
  }

  @Test
  fun testFromReaderHelloVerifyRequest() {
    val records = loadPackageData("cap/01_hello_verify_request.txt")
    assertEquals(1, records.size)
  }

  @Test
  fun testFromReaderClientHello1() {
    val records = loadPackageData("cap/03_client_hello.txt")
    assertEquals(1, records.size)
  }

  @Test
  fun testFromReaderFrame() {
    val records = loadPackageData("cap/04_frame_01.txt")
    assertEquals(5, records.size)
    val record = records[1]
    assertTrue(record.followUpRecord)
  }

  @Test
  fun testFromReaderConnectionID() {
    val records = loadPackageData("cap/08_frame_05.txt")
    assertEquals(1, records.size)
    val record = records.first()
    assertNotNull(record.connectionId)
  }

  private fun loadPackageData(path: String): List<Record> {
    val hexPath = javaClass.classLoader.getResource(path)?.toURI()!!
    val file = Files.readString(hexPath.toPath()).trim()
    val byteArray = Utility.hex2ByteArray(file)
    val reader = DatagramReader(byteArray)
    return Record.fromReader(reader, DefaultConnectionIdGenerator(6), ClockUtil.nanoRealtime())
  }

  private fun newGenericAEADCipherFragment(): ByteArray {
    // 64bit sequence number, consisting of 16bit epoch (0) + 48bit sequence number (5)
    val seqNum = byteArrayOf(0x00, EPOCH.toByte(), 0x00, 0x00, 0x00, 0x00, 0x00, SEQUENCE_NO.toByte())

    // additional data based on sequence number, type (APPLICATION DATA) and protocol version
    var additionalData =
      byteArrayOf(
        TYPE_APPL_DATA.toByte(),
        protocolVer.major.toByte(),
        protocolVer.minor.toByte(),
        0,
        payloadLength.toByte(),
      )
    additionalData = Bytes.concatenate(seqNum, additionalData)

    // "explicit" part of nonce, intentionally different from seq_num which MAY be used as the explicit nonce
    // but does not need to be used (at least that's my interpretation of the specs)
    val explicitNonce = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
    // nonce used for encryption, "implicit" part + "explicit" part
    val nonce = Bytes.concatenate(clientIv, explicitNonce)

    val encryptedData = CcmBlockCipher.encrypt(key, nonce, additionalData, payloadData, 8)

    // prepend the "explicit" part of nonce to the encrypted data to form the GenericAEADCipher struct
    return Bytes.concatenate(explicitNonce, encryptedData)
  }
}
