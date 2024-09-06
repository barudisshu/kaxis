/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.store

import io.kaxis.auth.PreSharedKeyIdentity
import io.kaxis.auth.RawPublicKeyIdentity
import io.kaxis.auth.X509CertPath
import io.kaxis.dtls.*
import io.kaxis.dtls.ConnectionId
import io.kaxis.dtls.DtlsTestTools
import io.kaxis.dtls.cipher.*
import io.kaxis.fsm.State
import io.kaxis.util.SecretIvParameterSpec
import io.kaxis.util.SecretUtil
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import java.security.InvalidAlgorithmParameterException
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

internal class StateSerializerTest {
  companion object {
    private val RANDOM = java.util.Random()
    private val COUNTER = AtomicInteger()

    fun newEstablishedServerDtlsContext(
      cipherSuite: CipherSuite,
      type: CertificateType,
    ): DTLSContext {
      var macKey: SecretKey? = null
      if (cipherSuite.macKeyLength > 0) {
        macKey = SecretKeySpec(getRandomBytes(cipherSuite.macKeyLength), "AES")
      }
      val encryptionKey = SecretKeySpec(getRandomBytes(cipherSuite.encKeyLength), "AES")
      val iv = SecretIvParameterSpec(getRandomBytes(cipherSuite.fixedIvLength))

      val session = newEstablishedServerSession(cipherSuite, type)
      val context = DTLSContext(0, false)
      context.session.set(session)
      SecretUtil.destroy(session)
      context.createReadState(encryptionKey, iv, macKey)
      context.createWriteState(encryptionKey, iv, macKey)
      return context
    }

    fun reload(context: DTLSContext): DTLSContext? {
      val writer = io.kaxis.util.DatagramWriter()
      if (context.writeTo(writer)) {
        val reader = io.kaxis.util.DatagramReader(writer.toByteArray())
        return DTLSContext.fromReader(reader)
      }
      return null
    }

    fun getRandomBytes(length: Int): ByteArray {
      val result = ByteArray(length)
      RANDOM.nextBytes(result)
      return result
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
            generator.initialize(ECGenParameterSpec("secp256r1"))
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
  }

  lateinit var context: DTLSContext

  @BeforeEach
  fun setUp() {
    context = newEstablishedServerDtlsContext(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CertificateType.X_509)
  }

  @Test
  fun testSerialization() {
    val state = State()
    var serialized = StateSerializer.toByteArray(state)
    var state1 = StateSerializer.toState(serialized)
    assertEquals(state, state1)

    state.stage = State.Stage.S0
    serialized = StateSerializer.toByteArray(state)
    state1 = StateSerializer.toState(serialized)
    assertEquals(state, state1)

    state.resumptionRequired = true
    serialized = StateSerializer.toByteArray(state)
    state1 = StateSerializer.toState(serialized)
    assertEquals(state, state1)

    state.peerAddress = InetSocketAddress("10.0.0.1", 8652)
    serialized = StateSerializer.toByteArray(state)
    state1 = StateSerializer.toState(serialized)
    assertEquals(state, state1)

    state.cid = ConnectionId(byteArrayOf(0x01, 0x02, 0x03, 0x04))
    serialized = StateSerializer.toByteArray(state)
    state1 = StateSerializer.toState(serialized)
    assertEquals(state, state1)

    state.dtlsContext = context
    serialized = StateSerializer.toByteArray(state)
    state1 = StateSerializer.toState(serialized)
    assertEquals(state, state1)
  }
}
