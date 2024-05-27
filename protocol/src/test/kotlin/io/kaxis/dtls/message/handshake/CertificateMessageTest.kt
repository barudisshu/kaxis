/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.message.handshake

import io.kaxis.Bytes
import io.kaxis.dtls.CertificateType
import io.kaxis.dtls.DtlsTestTools
import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.PublicKey
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

internal class CertificateMessageTest {
  lateinit var message: CertificateMessage
  lateinit var certificateChain: Array<X509Certificate>
  lateinit var trustAnchor: Array<X509Certificate>
  lateinit var serializedMessage: ByteArray
  lateinit var serverPublicKey: PublicKey

  @BeforeEach
  fun setUp() {
    certificateChain = DtlsTestTools.getServerCertificateChain()
    serverPublicKey = DtlsTestTools.getPublicKey()
    trustAnchor = DtlsTestTools.getTrustedCertificates()
  }

  @Test
  fun testCertificateMessageDoesNotContainRootCert() {
    val chain = DtlsTestTools.getServerCertificateChain()
    assertTrue(chain.size > 1)
    givenACertificateMessage(DtlsTestTools.getServerCertificateChain(), false)

    var issuer: X500Principal? = null
    message.certificateChain?.certificates?.forEach { c ->
      assertInstanceOf(X509Certificate::class.java, c)
      val cert = c as X509Certificate
      assertNotEquals(cert.issuerX500Principal, cert.subjectX500Principal)
      if (issuer != null) {
        assertEquals(cert.subjectX500Principal, issuer)
      }
      issuer = cert.issuerX500Principal
    }
  }

  @Test
  fun testEmptyCertificateMessageSerialization() {
    givenAnEmptyCertificateMessage()
    assertSerializedMessageLength(3)

    givenAnEmptyRawPublicKeyCertificateMessage()
    assertSerializedMessageLength(3)
  }

  @Test
  fun testFromByteArrayHandlessEmptyMessageCorrectly() {
    serializedMessage = byteArrayOf(0x00, 0x00, 0x00) // length = 0 (empty message)
    // parse expecting X.509 payload
    message = CertificateMessage.fromReader(DatagramReader(serializedMessage), CertificateType.X_509)
    assertSerializedMessageLength(3)

    // parse expecting RawPublicKey payload
    message =
      CertificateMessage.fromReader(
        DatagramReader(serializedMessage),
        CertificateType.RAW_PUBLIC_KEY,
      )
    assertSerializedMessageLength(3)
  }

  /**
   * Verify that a serialized certificate message containing a raw public key as specified in RFC 7250 section 3
   * can be parsed successfully.
   */
  @Test
  fun testFromByteArrayCompliesWithRfc7250() {
    givenASerializedRawPublicKeyCertificateMessage(serverPublicKey)
    message =
      CertificateMessage.fromReader(
        DatagramReader(serializedMessage),
        CertificateType.RAW_PUBLIC_KEY,
      )
    assertEquals(serverPublicKey, message.publicKey)
  }

  @Test
  fun testFragmentToByteArrayCompliesWithRfc7250() {
    givenARawPublicKeyCertificateMessage(serverPublicKey)
    serializedMessage = message.fragmentToByteArray()
    val rpkLength = serverPublicKey.encoded.size
    assertEquals(serializedMessage.size, rpkLength + 3)

    val reader = DatagramReader(serializedMessage)
    val length = reader.readLong(24)
    assertEquals(rpkLength.toLong(), length)
  }

  @Test
  fun testSerializationUsingRawPublicKey() {
    givenACertificateMessage(DtlsTestTools.getServerCertificateChain(), true)
    val parameter =
      HandshakeParameter(
        CipherSuite.KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN,
        CertificateType.RAW_PUBLIC_KEY,
      )
    val pk = message.publicKey
    assertNotNull(pk)
    serializedMessage = message.toByteArray()!!
    val msg = DtlsTestTools.fromByteArray<CertificateMessage>(serializedMessage, parameter)
    assertEquals(pk, msg.publicKey)
  }

  @Test
  fun testSerializationUsingX509() {
    givenACertificateMessage(DtlsTestTools.getServerCertificateChain(), false)
    val parameter = HandshakeParameter(CipherSuite.KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, CertificateType.X_509)
    val pk = message.publicKey
    assertNotNull(pk)
    serializedMessage = message.toByteArray()!!
    val msg = DtlsTestTools.fromByteArray<CertificateMessage>(serializedMessage, parameter)
    assertEquals(pk, msg.publicKey)
  }

  private fun assertSerializedMessageLength(length: Int) {
    assertEquals(length, message.messageLength)
    val serializedMsg = message.fragmentToByteArray()
    assertEquals(length, serializedMsg.size)
  }

  private fun givenACertificateMessage(
    chain: Array<X509Certificate>,
    useRawPublicKey: Boolean,
  ) {
    certificateChain = chain
    message =
      if (useRawPublicKey) {
        CertificateMessage(chain[0].publicKey.encoded)
      } else {
        CertificateMessage(chain.toList())
      }
  }

  private fun givenARawPublicKeyCertificateMessage(publicKey: PublicKey) {
    message = CertificateMessage(publicKey.encoded)
  }

  private fun givenASerializedRawPublicKeyCertificateMessage(publicKey: PublicKey) {
    val rawPublicKey = publicKey.encoded
    val writer = DatagramWriter()
    writer.writeLong(rawPublicKey.size.toLong(), 24)
    writer.writeBytes(rawPublicKey)
    serializedMessage = writer.toByteArray()
  }

  private fun givenAnEmptyCertificateMessage() {
    message = CertificateMessage()
  }

  private fun givenAnEmptyRawPublicKeyCertificateMessage() {
    message = CertificateMessage(Bytes.EMPTY_BYTES)
  }
}
