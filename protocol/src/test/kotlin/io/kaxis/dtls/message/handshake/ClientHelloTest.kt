/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.message.handshake

import io.kaxis.dtls.CertificateType
import io.kaxis.dtls.CompressionMethod
import io.kaxis.dtls.ProtocolVersion
import io.kaxis.dtls.SignatureAndHashAlgorithm
import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.dtls.cipher.XECDHECryptography
import io.kaxis.dtls.extensions.ExtendedMasterSecretExtension
import io.kaxis.util.SecretUtil
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test
import java.security.GeneralSecurityException
import java.security.SecureRandom
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

internal class ClientHelloTest {
  companion object {
    fun createClientHello(
      supportedCipherSuites: MutableList<CipherSuite>,
      supportedSignatureAndHashAlgorithms: MutableList<SignatureAndHashAlgorithm>,
      supportedClientCertTypes: MutableList<CertificateType>,
      supportedServerCertTypes: MutableList<CertificateType>,
      supportedGroups: MutableList<XECDHECryptography.SupportedGroup>,
    ): ClientHello =
      ClientHello(
        ProtocolVersion.VERSION_DTLS_1_2,
        supportedCipherSuites,
        supportedSignatureAndHashAlgorithms,
        supportedClientCertTypes,
        supportedServerCertTypes,
        supportedGroups,
      )
  }

  lateinit var clientHello: ClientHello

  /**
   * Verifies that the calculated message length is the same as the length of the serialized message.
   */
  @Test
  fun testGetMessageLengthEqualsSerializedMessageLength() {
    givenAClientHelloWithEmptyExtensions()
    assertEquals(clientHello.messageLength, clientHello.fragmentToByteArray().size)
  }

  /**
   * Verifies that a ClientHello message does not contain point_format and elliptic_curves extensions if only
   * non-ECC based cipher suites are supported.
   */
  @Test
  fun testConstructorOmitsEccExtensionsForNonEccBasedCipherSuites() {
    givenAClientHello(
      mutableListOf(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256),
      SignatureAndHashAlgorithm.DEFAULT,
      mutableListOf(),
      mutableListOf(),
      mutableListOf(XECDHECryptography.SupportedGroup.secp256r1),
    )
    assertNull(
      clientHello.supportedEllipticCurvesExtension,
      "ClientHello should not contain elliptic_curves extension for non-ECC based cipher suites",
    )
    assertNull(
      clientHello.supportedPointFormatsExtension,
      "ClientHello should not contain point_format extension for non-ECC based cipher suites",
    )
  }

  /**
   * Verifies that a ClientHello message contains point_format and elliptic_curves
   * extensions if an ECC based cipher suite is supported.
   */
  @Test
  fun testConstructorAddsEccExtensionsForEccBasedCipherSuites() {
    givenAClientHello(
      mutableListOf(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256),
      SignatureAndHashAlgorithm.DEFAULT,
      mutableListOf(),
      mutableListOf(),
      mutableListOf(XECDHECryptography.SupportedGroup.secp256r1),
    )
    assertNotNull(
      clientHello.supportedEllipticCurvesExtension,
      "ClientHello should contain elliptic_curves extension for ECC based cipher suites",
    )
    assertNotNull(
      clientHello.supportedPointFormatsExtension,
      "ClientHello should contain point_format extension for ECC based cipher suites",
    )
  }

  /**
   * Verifies updating the Cookie for a ClientHello message.
   *
   * Verifies, that for a ClientHello without a cookie in the message, with a
   * cookie in the message and with extensions results in the same calculated
   * cookie.
   *
   * @throws GeneralSecurityException if calculating the cookie fails
   */
  @Test
  @Throws(GeneralSecurityException::class)
  fun testUpdateCookie() {
    val randomGenerator = SecureRandom()

    givenAClientHelloWithEmptyExtensions()

    val randomBytes = ByteArray(32)
    randomGenerator.nextBytes(randomBytes)
    val key = SecretUtil.create(randomBytes, "MAC")

    // no cookie, no extension
    val hmac = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256.threadLocalMac ?: throw GeneralSecurityException()
    hmac.init(key)
    clientHello.updateForCookie(hmac)
    val mac1 = hmac.doFinal()

    // with cookie, no extension
    randomGenerator.nextBytes(randomBytes)
    clientHello.cookie = randomBytes

    hmac.init(key)
    clientHello.updateForCookie(hmac)
    var mac2 = hmac.doFinal()
    assertArrayEquals(mac1, mac2)

    // with cookie, with extension
    clientHello.addExtension(ExtendedMasterSecretExtension.INSTANCE)
    clientHello.fragmentChanged()

    hmac.init(key)
    clientHello.updateForCookie(hmac)
    mac2 = hmac.doFinal()
    assertArrayEquals(mac1, mac2)

    SecretUtil.destroy(key)
  }

  private fun givenAClientHelloWithEmptyExtensions() {
    clientHello =
      ClientHello(
        ProtocolVersion.VERSION_DTLS_1_2,
        mutableListOf(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256),
        mutableListOf(),
        mutableListOf(),
        mutableListOf(),
        mutableListOf(),
      )
    clientHello.addCompressionMethod(CompressionMethod.NULL)
  }

  private fun givenAClientHello(
    supportedCipherSuites: MutableList<CipherSuite>,
    supportedSignatureAndHashAlgorithms: MutableList<SignatureAndHashAlgorithm>,
    supportedClientCertTypes: MutableList<CertificateType>,
    supportedServerCertTypes: MutableList<CertificateType>,
    supportedGroups: MutableList<XECDHECryptography.SupportedGroup>,
  ) {
    clientHello =
      createClientHello(
        supportedCipherSuites,
        supportedSignatureAndHashAlgorithms,
        supportedClientCertTypes,
        supportedServerCertTypes,
        supportedGroups,
      )
  }
}
