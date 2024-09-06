/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
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
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

internal class AbstractDtlsServerTest : DtlsInitTest() {
  private lateinit var dtlsServer: AbstractDtlsServer
  private val mutualAuthentication = AtomicBoolean(true)

  @BeforeEach
  fun setUp() {
    val bcTlsCrypto = BcTlsCrypto(CryptoServicesRegistrar.getSecureRandom())
    val caBcCertificate = caContent.asCertificate(bcTlsCrypto)
    val serverBcCertificate = serverContent.asCertificate(bcTlsCrypto)
    val serverBcAsymmetricKeyParameter = serverKeyContent.asAsymmetricKeyParameter()

    dtlsServer =
      object : AbstractDtlsServer() {
        override fun isMutualAuthentication(): Boolean = mutualAuthentication.get()

        override fun getServerCaCert(): Certificate = caBcCertificate

        override fun getServerPrivateKey(): AsymmetricKeyParameter = serverBcAsymmetricKeyParameter

        override fun getServerCert(): Certificate = serverBcCertificate
      }
  }

  @Test
  fun commonPlaceTest() {
    assertTrue(dtlsServer.isMutualAuthentication())
    assertEquals(2, dtlsServer.supportedVersions.size)
    assertEquals(HeartbeatMode.peer_allowed_to_send, dtlsServer.heartbeatPolicy)
    assertEquals(10000, dtlsServer.heartbeat.idleMillis)
    assertEquals(10000, dtlsServer.heartbeat.timeoutMillis)
    assertEquals(RenegotiationPolicy.DENY, dtlsServer.renegotiationPolicy)
    assertFalse(dtlsServer.shouldUseExtendedPadding())
  }

  @Test
  fun notifyAlertRaisedTest() {
    assertDoesNotThrow {
      dtlsServer.notifyAlertRaised(
        AlertLevel.fatal,
        AlertDescription.bad_certificate,
        "unknown error",
        TlsFatalAlert(AlertDescription.internal_error),
      )
    }
  }

  @Test
  fun notifyAlertReceivedTest() {
    assertDoesNotThrow {
      dtlsServer.notifyAlertReceived(
        AlertLevel.fatal,
        AlertDescription.bad_certificate,
      )
    }
  }

  @Test
  @Throws(IOException::class)
  fun notifyClientCertificateTest() {
    mutualAuthentication.compareAndSet(true, false)

    val certificate =
      Certificate(
        arrayOf(
          dtlsServer.getServerCert().getCertificateAt(0),
          dtlsServer.getServerCaCert().getCertificateAt(0),
        ),
      )
    assertDoesNotThrow {
      dtlsServer.notifyClientCertificate(
        certificate,
      )
    }
    mutualAuthentication.compareAndSet(false, true)
    assertThrows(
      NullPointerException::class.java,
    ) { dtlsServer.notifyClientCertificate(certificate) }
  }

  @Test
  fun getCredentialsTest() {
    assertThrows(
      NullPointerException::class.java,
    ) { dtlsServer.credentials }
  }
}
