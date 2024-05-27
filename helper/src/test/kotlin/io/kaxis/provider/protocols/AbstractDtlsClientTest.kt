/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.provider.protocols

import io.kaxis.asAsymmetricKeyParameter
import io.kaxis.asCertificate
import org.bouncycastle.crypto.CryptoServicesRegistrar
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.tls.*
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicBoolean

internal class AbstractDtlsClientTest : DtlsInitTest() {
  private lateinit var dtlsClient: AbstractDtlsClient
  private val mutualAuthentication = AtomicBoolean(true)

  @BeforeEach
  fun setUp() {
    val bcTlsCrypto = BcTlsCrypto(CryptoServicesRegistrar.getSecureRandom())
    val caBcCertificate = caContent.asCertificate(bcTlsCrypto)
    val clientBcCertificate = clientContent.asCertificate(bcTlsCrypto)
    val clientBcAsymmetricKeyParam = clientKeyContent.asAsymmetricKeyParameter()

    dtlsClient =
      object : AbstractDtlsClient() {
        override fun isMutualAuthentication(): Boolean = mutualAuthentication.get()

        override fun getClientCaCert(): Certificate = caBcCertificate

        override fun getClientPrivateKey(): AsymmetricKeyParameter = clientBcAsymmetricKeyParam

        override fun getClientCert(): Certificate = clientBcCertificate
      }
  }

  @Test
  fun commonPlaceTest() {
    assertTrue(dtlsClient.isMutualAuthentication())
    assertEquals(2, dtlsClient.supportedVersions.size)
    assertEquals(HeartbeatMode.peer_allowed_to_send, dtlsClient.heartbeatPolicy)
    assertEquals(10000, dtlsClient.heartbeat.idleMillis)
    assertEquals(10000, dtlsClient.heartbeat.timeoutMillis)
    assertEquals(RenegotiationPolicy.DENY, dtlsClient.renegotiationPolicy)
    assertFalse(dtlsClient.shouldUseExtendedPadding())
  }

  @Test
  fun notifyAlertReceivedTest() {
    assertDoesNotThrow {
      dtlsClient.notifyAlertReceived(
        AlertLevel.fatal,
        AlertDescription.bad_certificate,
      )
    }
  }
}
