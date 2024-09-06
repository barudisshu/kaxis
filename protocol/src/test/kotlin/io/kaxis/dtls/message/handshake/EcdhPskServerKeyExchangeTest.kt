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
import io.kaxis.dtls.DtlsTestTools
import io.kaxis.dtls.PskPublicInformation
import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.dtls.cipher.XECDHECryptography
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

internal class EcdhPskServerKeyExchangeTest {
  private lateinit var msg: EcdhPskServerKeyExchange
  private lateinit var ephemeralPubKey: ByteArray

  @BeforeEach
  fun setUp() {
    val usableGroup = XECDHECryptography.SupportedGroup.secp256r1
    msg = EcdhPskServerKeyExchange(PskPublicInformation.EMPTY, XECDHECryptography(usableGroup))
    ephemeralPubKey = msg.encodedPoint
  }

  @Test
  fun testInstanceToString() {
    val toString = msg.toString()
    assertNotNull(toString)
  }

  @Test
  fun testDeserializedMsg() {
    val serializedMsg = msg.toByteArray()
    val parameter = HandshakeParameter(CipherSuite.KeyExchangeAlgorithm.ECDHE_PSK, CertificateType.X_509)
    val handshakeMsg = DtlsTestTools.fromByteArray<EcdhPskServerKeyExchange>(serializedMsg, parameter)
    assertEquals(handshakeMsg.supportedGroup.id, XECDHECryptography.SupportedGroup.secp256r1.id)
    assertNotNull(ephemeralPubKey)
    assertArrayEquals(handshakeMsg.encodedPoint, ephemeralPubKey)
  }
}
