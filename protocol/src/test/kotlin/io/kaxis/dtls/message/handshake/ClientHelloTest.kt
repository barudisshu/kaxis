/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.message.handshake

import io.kaxis.dtls.CertificateType
import io.kaxis.dtls.ProtocolVersion
import io.kaxis.dtls.SignatureAndHashAlgorithm
import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.dtls.cipher.XECDHECryptography
import org.junit.jupiter.api.Test
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
    ): ClientHello {
      return ClientHello(
        ProtocolVersion.VERSION_DTLS_1_2,
        supportedCipherSuites,
        supportedSignatureAndHashAlgorithms,
        supportedClientCertTypes,
        supportedServerCertTypes,
        supportedGroups,
      )
    }
  }

  lateinit var clientHello: ClientHello

  private fun givenAClientHelloWithEmptyExtensions() {
    clientHello =
      ClientHello(
        ProtocolVersion.VERSION_DTLS_1_2,
        mutableListOf(),
        SignatureAndHashAlgorithm.DEFAULT,
        null,
        null,
        mutableListOf(),
      )
  }

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
