/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.message.handshake

import io.kaxis.dtls.CertificateType
import io.kaxis.dtls.DtlsTestTools
import io.kaxis.dtls.Random
import io.kaxis.dtls.SignatureAndHashAlgorithm
import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.dtls.cipher.XECDHECryptography
import io.kaxis.dtls.message.HandshakeMessage
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

internal class ECDHServerKeyExchangeTest {
  private lateinit var msg: EcdhSignedServerKeyExchange

  @BeforeEach
  fun setUp() {
    val usableGroup = XECDHECryptography.SupportedGroup.getUsableGroups()[0]
    msg =
      EcdhSignedServerKeyExchange(
        SignatureAndHashAlgorithm(
          SignatureAndHashAlgorithm.HashAlgorithm.SHA256,
          SignatureAndHashAlgorithm.SignatureAlgorithm.ECDSA,
        ),
        XECDHECryptography(usableGroup),
        DtlsTestTools.getPrivateKey(),
        Random(),
        Random(),
      )
  }

  @Test
  fun testInstanceToString() {
    val toString = msg.toString()
    assertNotNull(toString)
  }

  @Test
  fun testDeserializedInstanceToString() {
    val serializedMsg = msg.toByteArray()
    val parameter =
      HandshakeParameter(CipherSuite.KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, CertificateType.RAW_PUBLIC_KEY)
    val handshakeMsg = DtlsTestTools.fromByteArray<HandshakeMessage>(serializedMsg, parameter)
    assertNotNull(handshakeMsg)
  }
}
