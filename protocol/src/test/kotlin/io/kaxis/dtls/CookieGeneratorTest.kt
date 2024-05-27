/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls

import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.dtls.cipher.XECDHECryptography
import io.kaxis.dtls.message.handshake.ClientHelloTest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress

internal class CookieGeneratorTest {
  private lateinit var generator: CookieGenerator
  private lateinit var peerAddress: InetSocketAddress
  private lateinit var peerAddress2: InetSocketAddress

  @BeforeEach
  fun setUp() {
    peerAddress = InetSocketAddress("localhost", 5684)
    peerAddress2 = InetSocketAddress("localhost", 5685)
    generator = CookieGenerator()
  }

  @Test
  fun testCookieGeneratorGeneratesSameCookie() {
    val clientHello =
      ClientHelloTest.createClientHello(
        mutableListOf(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256),
        SignatureAndHashAlgorithm.DEFAULT,
        mutableListOf(),
        mutableListOf(),
        mutableListOf(XECDHECryptography.SupportedGroup.secp256r1),
      )
    val cookie1 = generator.generateCookie(peerAddress, clientHello)
    clientHello.cookie = cookie1

    val cookie2 = generator.generateCookie(peerAddress, clientHello)
    assertArrayEquals(cookie1, cookie2)
  }
}
