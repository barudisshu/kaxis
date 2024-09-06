/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls

import io.kaxis.Bytes
import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.dtls.cipher.RandomManager
import io.kaxis.dtls.message.ApplicationMessage
import io.kaxis.exception.HandshakeException
import io.kaxis.util.ClockUtil
import io.kaxis.util.DatagramWriter
import io.kaxis.util.SecretIvParameterSpec
import io.kaxis.util.SecretUtil
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.security.GeneralSecurityException
import javax.crypto.spec.SecretKeySpec
import kotlin.math.min

internal class RecordDecryptTest {
  companion object {
    const val TYPE_APPL_DATA = 23
    const val EPOCH = 1
    const val DUMP = false

    @JvmStatic
    fun cipherSuiteParams(): List<CipherSuite> {
      return listOf(
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
      )
    }
  }

  lateinit var context: DTLSContext
  lateinit var payloadData: ByteArray
  var payloadLength: Int = 128

  private fun provisioning(cipherSuite: CipherSuite) {
    val secureRandom = RandomManager.currentSecureRandom()
    check(cipherSuite.isSupported) { "cipher suite ${cipherSuite.name} is not supported!" }
    val encKeyLength = cipherSuite.encKeyLength
    val macKeyLength = cipherSuite.macKeyLength
    val ivLength = cipherSuite.fixedIvLength
    val encKey = SecretKeySpec(Bytes.createBytes(secureRandom, encKeyLength), "AES")
    val macKey = if (macKeyLength == 0) null else SecretKeySpec(Bytes.createBytes(secureRandom, macKeyLength), "AES")
    val iv = if (ivLength > 0) SecretIvParameterSpec(Bytes.createBytes(secureRandom, ivLength)) else null
    payloadData = Bytes.createBytes(secureRandom, payloadLength)

    val session = DTLSSession()
    session.cipherSuite = cipherSuite
    session.compressionMethod = CompressionMethod.NULL
    context = DTLSContext(0, false)
    context.session = session
    SecretUtil.destroy(session)
    context.createReadState(encKey, iv, macKey)
    context.createWriteState(encKey, iv, macKey)
  }

  /**
   * Test, if payload of different sizes could be encrypted and decrypted.
   */
  @ParameterizedTest
  @MethodSource("cipherSuiteParams")
  fun testEncryptDecrypt(cipherSuite: CipherSuite) {
    provisioning(cipherSuite)

    for (size in 1..<payloadLength) {
      val payload = payloadData.copyOf(size)
      val record = Record(ContentType.APPLICATION_DATA, EPOCH, ApplicationMessage(payload), context, true, 0)
      val raw = record.toByteArray()
      val list = DtlsTestTools.fromByteArray(raw, null, ClockUtil.nanoRealtime())
      assertTrue(list.isNotEmpty())
      list.forEach { recv ->
        recv.decodeFragment(context.readState)
        val message = recv.fragment
        assertArrayEquals(payload, message!!.toByteArray()) { "decrypted payload differs" }
      }
    }
  }

  @ParameterizedTest
  @MethodSource("cipherSuiteParams")
  fun testEncryptDecryptRecordLengthFailure(cipherSuite: CipherSuite) {
    provisioning(cipherSuite)
    testEncryptDecryptRecordFailure(LengthJuggler())
  }

  @ParameterizedTest
  @MethodSource("cipherSuiteParams")
  fun testEncryptDecryptFragmentLengthFailure(cipherSuite: CipherSuite) {
    provisioning(cipherSuite)
    testEncryptDecryptFragmentFailure(LengthJuggler())
  }

  @ParameterizedTest
  @MethodSource("cipherSuiteParams")
  fun testEncryptDecryptFragmentAllLengthFailure(cipherSuite: CipherSuite) {
    provisioning(cipherSuite)
    for (size in 15..(32 + 16)) {
      val payload = payloadData.copyOf(size)
      for (delta in -size..<size + 10) {
        try {
          testEncryptDecryptFragmentFailure(payload, FixedLengthJuggler(delta))
        } catch (ex: Throwable) {
          // IGNORED
        }
      }
    }
  }

  @ParameterizedTest
  @MethodSource("cipherSuiteParams")
  fun testEncryptDecryptRecordBytesFailure(cipherSuite: CipherSuite) {
    provisioning(cipherSuite)
    testEncryptDecryptRecordFailure(BytesJuggler(5))
  }

  @ParameterizedTest
  @MethodSource("cipherSuiteParams")
  fun testEncryptDecryptFragmentBytesFailure(cipherSuite: CipherSuite) {
    provisioning(cipherSuite)
    testEncryptDecryptFragmentFailure(BytesJuggler(5))
  }

  @ParameterizedTest
  @MethodSource("cipherSuiteParams")
  fun testEncryptDecryptRecordCombiFailure(cipherSuite: CipherSuite) {
    provisioning(cipherSuite)
    testEncryptDecryptRecordFailure(CombiJuggler(5))
  }

  @ParameterizedTest
  @MethodSource("cipherSuiteParams")
  fun testEncryptDecryptFragmentCombiFailure(cipherSuite: CipherSuite) {
    provisioning(cipherSuite)
    testEncryptDecryptFragmentFailure(CombiJuggler(5))
  }

  private fun testEncryptDecryptRecordFailure(juggler: Juggler) {
    for (size in 1..<payloadLength) {
      val payload = payloadData.copyOf(size)
      try {
        testEncryptDecryptRecordFailure(payload, juggler)
      } catch (ex: Throwable) {
        // IGNORE
      }
    }
  }

  @Throws(GeneralSecurityException::class, HandshakeException::class)
  private fun testEncryptDecryptRecordFailure(
    payload: ByteArray,
    juggler: Juggler,
  ) {
    val record = Record(ContentType.APPLICATION_DATA, EPOCH, ApplicationMessage(payload), context, true, 0)
    val raw = record.toByteArray()
    val jraw = juggler.juggle(raw)
    dumpDiff(raw, jraw)
    val list = DtlsTestTools.fromByteArray(jraw, null, ClockUtil.nanoRealtime())
    list.forEach { recv ->
      if (recv.epoch != EPOCH) return@forEach
      recv.decodeFragment(context.readState)
      recv.fragment
    }
  }

  private fun testEncryptDecryptFragmentFailure(juggler: Juggler) {
    for (size in 1..<payloadLength) {
      val payload = payloadData.copyOf(size)
      try {
        testEncryptDecryptFragmentFailure(payload, juggler)
      } catch (ex: Throwable) {
        // IGNORE
      }
    }
  }

  private fun testEncryptDecryptFragmentFailure(
    payload: ByteArray,
    juggler: Juggler,
  ) {
    val record = Record(ContentType.APPLICATION_DATA, EPOCH, ApplicationMessage(payload), context, true, 0)
    val fragment = record.fragmentBytes!!
    val jfragment = juggler.juggle(fragment)
    dumpDiff(fragment, jfragment)
    val raw = toByteArray(record, jfragment)
    val list = DtlsTestTools.fromByteArray(raw, null, ClockUtil.nanoRealtime())
    list.forEach { recv ->
      recv.decodeFragment(context.readState)
      recv.fragment
    }
  }

  private fun toByteArray(
    record: Record,
    fragment: ByteArray,
  ): ByteArray {
    val writer = DatagramWriter()
    if (record.useConnectionId) {
      writer.write(ContentType.TLS12_CID.code, Record.CONTENT_TYPE_BITS)
    } else {
      writer.write(record.type.code, Record.CONTENT_TYPE_BITS)
    }

    writer.write(record.version.major, Record.VERSION_BITS)
    writer.write(record.version.minor, Record.VERSION_BITS)

    writer.write(record.epoch, Record.EPOCH_BITS)
    writer.writeLong(record.sequenceNumber, Record.SEQUENCE_NUMBER_BITS)
    if (record.useConnectionId) {
      writer.writeBytes(record.connectionId!!.byteArray)
    }
    writer.write(fragment.size, Record.LENGTH_BITS)
    writer.writeBytes(fragment)

    return writer.toByteArray()
  }

  fun dumpDiff(
    data1: ByteArray,
    data2: ByteArray,
  ) {
    if (DUMP) {
      if (!data1.contentEquals(data2)) {
        val line = StringBuilder()
        var end = data1.size
        if (end != data2.size) {
          end = min(data1.size, data2.size)
          line.append("[%d!=%d]".format(data1.size, data2.size))
        }
        for (index in 0..<end) {
          if (data1[index] != data2[index]) {
            line.append("[%d%02x!=%02x".format(index, data1[index].toInt() and 0xff, data2[index].toInt() and 0xff))
          }
        }
        println(line)
      }
    }
  }

  interface Juggler {
    fun juggle(data: ByteArray): ByteArray
  }

  class FixedLengthJuggler(private val delta: Int) : Juggler {
    override fun juggle(data: ByteArray): ByteArray {
      var length = data.size + delta
      if (length < 0) {
        length = 0
      }
      return data.copyOf(length)
    }
  }

  class LengthJuggler : Juggler {
    private val secureRandom = RandomManager.currentSecureRandom()

    override fun juggle(data: ByteArray): ByteArray {
      return data.copyOf(secureRandom.nextInt(data.size + 32))
    }
  }

  class BytesJuggler(private val count: Int) : Juggler {
    private val secureRandom = RandomManager.currentSecureRandom()

    override fun juggle(data: ByteArray): ByteArray {
      var data0 = data
      if (data0.isNotEmpty()) {
        data0 = data0.copyOf(data0.size)
        for (mods in 0..<count) {
          val index = secureRandom.nextInt(data0.size)
          data0[index] = secureRandom.nextInt(256).toByte()
        }
      }
      return data0
    }
  }

  class CombiJuggler : Juggler {
    private val length = LengthJuggler()
    private val bytes: BytesJuggler

    constructor(count: Int) {
      this.bytes = BytesJuggler(count)
    }

    override fun juggle(data: ByteArray): ByteArray {
      var data0 = data
      data0 = length.juggle(data0)
      data0 = bytes.juggle(data0)
      return data
    }
  }
}
