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
import io.kaxis.auth.PreSharedKeyIdentity
import io.kaxis.auth.RawPublicKeyIdentity
import io.kaxis.auth.X509CertPath
import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.dtls.cipher.ThreadLocalKeyPairGenerator
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.InvalidAlgorithmParameterException
import java.security.spec.ECGenParameterSpec
import java.util.Random
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.spec.SecretKeySpec
import kotlin.test.assertEquals

internal class DTLSSessionTest {
  companion object {
    private val RANDOM = Random()
    private val COUNTER = AtomicInteger()

    fun assertThatSessionsHaveSameRelevantPropertiesForResumption(
      sessionToResume: DTLSSession,
      establishedSession: DTLSSession,
    ) {
      assertEquals(establishedSession.sessionIdentifier, sessionToResume.sessionIdentifier)
      assertEquals(sessionToResume.cipherSuite, establishedSession.cipherSuite)
      assertEquals(sessionToResume.compressionMethod, establishedSession.compressionMethod)
      assertEquals(sessionToResume.masterSecret, establishedSession.masterSecret)
      assertEquals(sessionToResume.peerIdentity, establishedSession.peerIdentity)
      assertEquals(sessionToResume.serverNames, establishedSession.serverNames)
    }

    fun newEstablishedServerSession(
      cipherSuite: CipherSuite,
      type: CertificateType,
    ): DTLSSession {
      val session = DTLSSession()
      session.sessionIdentifier = SessionId()
      session.cipherSuite = cipherSuite
      session.compressionMethod = CompressionMethod.NULL
      session.receiveCertificateType = type
      session.sendCertificateType = type
      session.masterSecret = SecretKeySpec(getRandomBytes(48), "MAC")
      if (cipherSuite.isPskBased) {
        session.peerIdentity = PreSharedKeyIdentity("client_identity_${COUNTER.incrementAndGet()}")
      } else {
        val chain = DtlsTestTools.getServerCertificateChain()
        if (type == CertificateType.RAW_PUBLIC_KEY) {
          var peer = chain[0].publicKey
          try {
            val keyPairGenerator = ThreadLocalKeyPairGenerator("EC")
            val generator = keyPairGenerator.current()!!
            generator.initialize(ECGenParameterSpec("secp384r1"))
            peer = generator.generateKeyPair().public
          } catch (e: InvalidAlgorithmParameterException) {
            // ignored
          }
          session.peerIdentity = RawPublicKeyIdentity(peer)
        } else {
          session.peerIdentity = X509CertPath.fromCertificateChain(chain.toList())
        }
      }
      return session
    }

    private fun reload(context: DTLSSession): DTLSSession? {
      val writer = DatagramWriter()
      context.writeTo(writer)
      val reader = DatagramReader(writer.toByteArray())
      return DTLSSession.fromReader(reader)
    }

    private fun getRandomBytes(length: Int): ByteArray {
      val result = ByteArray(length)
      RANDOM.nextBytes(result)
      return result
    }

    private fun serialize(session: DTLSSession): DTLSSession? {
      val writer = DatagramWriter(true)
      session.writeTo(writer)
      val ticketBytes = writer.toByteArray()
      val reader = DatagramReader(ticketBytes)
      val result = DTLSSession.fromReader(reader)
      Bytes.clear(ticketBytes)
      writer.close()
      return result
    }
  }

  lateinit var session: DTLSSession

  @BeforeEach
  fun setUp() {
    session = newEstablishedServerSession(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CertificateType.X_509)
  }

  @Test
  fun testDefaultMaxFragmentLengthCompliesWithSpec() {
    // WHEN instantiating a default server session
    session = DTLSSession()

    // THEN the max fragment size is as specified in DTLS spec
    assertEquals(Record.DTLS_MAX_PLAINTEXT_FRAGMENT_LENGTH, session.maxFragmentLength)
  }

  @Test
  fun testSessionCanBeResumedFromSession() {
    // GIVEN a session for an established server session
    session =
      newEstablishedServerSession(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CertificateType.RAW_PUBLIC_KEY)

    // WHEN creating a new session to be resumed from the session
    val sessionToResume = DTLSSession(session)

    // THEN the new session contains all relevant pending state to perform an abbreviated handshake
    assertThatSessionsHaveSameRelevantPropertiesForResumption(sessionToResume, session)
  }

  @Test
  fun testSessionWithServerNamesCanBeResumedFromSessionTicket() {
    // GIVEN a session with servername for an established server session
    session =
      newEstablishedServerSession(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CertificateType.RAW_PUBLIC_KEY)
    session.hostName = "test"

    // WHEN creating a new session to be resumed from the session
    val sessionToResume = DTLSSession(session)

    // THEN the new session contains all relevant pending state to perform an abbreviated handshake
    assertThatSessionsHaveSameRelevantPropertiesForResumption(sessionToResume, session)
  }

  @Test
  fun testSessionCanBeResumedFromSerializedSession() {
    // GIVEN a session ticket for an established server session
    session =
      newEstablishedServerSession(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CertificateType.RAW_PUBLIC_KEY)

    // WHEN creating a new session to be resumed from the serialized session
    val sessionToResume = serialize(session)!!

    // THEN the new session contains all relevant pending state to perform an abbreviated handshake
    assertThatSessionsHaveSameRelevantPropertiesForResumption(sessionToResume, session)
  }

  @Test
  fun testSessionWithServerNamesCanBeResumedFromSerializedSessionTicket() {
    // GIVEN a session ticket for an established server session
    session =
      newEstablishedServerSession(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CertificateType.RAW_PUBLIC_KEY)
    session.hostName = "test"

    // WHEN creating a new session to be resumed from the ticket
    val sessionToResume = serialize(session)!!

    // THEN the new session contains all relevant pending state to perform an abbreviated handshake
    assertThatSessionsHaveSameRelevantPropertiesForResumption(sessionToResume, session)
  }

  @Test
  fun testReloadEcdsaSession() {
    // GIVEN a session ticket for an established server session
    session =
      newEstablishedServerSession(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CertificateType.RAW_PUBLIC_KEY)
    session.hostName = "test"

    val session2 = reload(session)
    assertEquals(session, session2)
  }

  @Test
  fun testReloadPskSession() {
    // GIVEN a session ticket for an established server session
    session =
      newEstablishedServerSession(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CertificateType.RAW_PUBLIC_KEY)
    session.hostName = "test"

    // WHEN creating a new session to be resumed from the ticket
    val sessionToResume = serialize(session)!!

    // THEN the new session contains all relevant pending state to perform an abbreviated handshake
    assertThatSessionsHaveSameRelevantPropertiesForResumption(sessionToResume, session)
  }

  @Test
  fun testReloadEcdsaEd25519Session() {
    // GIVEN a session ticket for an established server session
    session =
      newEstablishedServerSession(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CertificateType.RAW_PUBLIC_KEY)
    session.hostName = "test"
    session.signatureAndHashAlgorithm = SignatureAndHashAlgorithm.INTRINSIC_WITH_ED25519

    val session2 = reload(session)
    assertEquals(session, session2)
  }
}
