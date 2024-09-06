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

import io.kaxis.ansi.Highlight
import io.kaxis.extension.AlgParameter
import io.kaxis.extension.DefaultKaxisBcJcaGenerator
import io.kaxis.extension.generator.KaxisBcFabric
import io.kaxis.extension.param.AlgEnum
import io.kaxis.extension.param.AlgEnum.EC
import io.kaxis.extension.param.AlgEnum.RSA
import io.kaxis.extension.param.AlgKeySizeEnum
import io.kaxis.extension.param.AlgKeySizeEnum.*
import io.kaxis.extension.param.Asn1OidEnum
import io.kaxis.extension.param.Asn1OidEnum.*
import io.kaxis.extension.param.SigAlgEnum
import io.kaxis.extension.param.SigAlgEnum.*
import org.awaitility.Awaitility
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.tls.*
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import org.junit.jupiter.api.*
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.security.spec.InvalidKeySpecException
import java.time.Duration
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@TestMethodOrder(value = MethodOrderer.DisplayName::class)
internal class IntegrateTest {
  companion object {
    private val isHandshakeFinish = AtomicBoolean(false)
    private const val MTU = 1500
    private const val PORT = 5684

    /**
     * Only support RSA, ECDSA protocol.
     */
    @JvmStatic
    fun getData(): List<Arguments> =
      listOf(
        Arguments.of(RSA, SHA_256_WITH_RSA, RSA_1024, AES_128_CBC),
        Arguments.of(RSA, SHA_1_WITH_RSA, RSA_2048, DES_EDE3_CBC),
        Arguments.of(RSA, SHA_256_WITH_RSA_AND_MGF1, RSA_1024, AES_128_CBC),
        Arguments.of(RSA, SHA_384_WITH_RSA_AND_MGF1, RSA_1024, AES_256_CBC),
        Arguments.of(RSA, SHA_512_WITH_RSA_AND_MGF1, RSA_2048, PBE_WITH_SHA_AND_128_BIT_RC4),
        Arguments.of(RSA, SHA_224_WITH_RSA_ENCRYPTION, RSA_1024, AES_192_CBC),
        Arguments.of(RSA, SHA_256_WITH_RSA_ENCRYPTION, RSA_1024, AES_128_CBC),
        Arguments.of(RSA, SHA_384_WITH_RSA_ENCRYPTION, RSA_1024, AES_256_CBC),
        Arguments.of(RSA, SHA_512_WITH_RSA_ENCRYPTION, RSA_2048, PBE_WITH_SHA_AND_128_BIT_RC4),
        Arguments.of(EC, SHA_1_WITH_ECDSA, EC_256, PBE_WITH_SHA_AND_2_KEY_TRIPLEDES_CBC),
        Arguments.of(EC, SHA_224_WITH_ECDSA, EC_224, AES_256_CBC),
        Arguments.of(EC, SHA_384_WITH_ECDSA, EC_384, AES_256_CBC),
        Arguments.of(EC, SHA_512_WITH_ECDSA, EC_256, AES_256_CBC),
      )
  }

  private lateinit var executorService: ExecutorService

  @BeforeEach
  fun setUp() {
    executorService = Executors.newWorkStealingPool()
  }

  @AfterEach
  fun tearDown() {
    executorService.shutdownNow()
  }

  @ParameterizedTest(
    name = "0{index}: algorithm: ''{0}'', signature algorithm: ''{1}'', asn1: ''{2}''",
  )
  @MethodSource("getData")
  @DisplayName("01 - Default.random")
  fun simpleTest(
    algEnum: AlgEnum,
    sigAlg: SigAlgEnum,
    keySize: AlgKeySizeEnum,
    asn1Oid: Asn1OidEnum,
  ) {
    val defaultKaxisBcJcaGenerator = DefaultKaxisBcJcaGenerator()
    val algParameter = AlgParameter(type = algEnum, algKeySize = keySize, sigAlg = sigAlg, asn1Oid = asn1Oid)
    assertEquals(asn1Oid, algParameter.asn1Oid)

    val jcaMiscPemGroove = defaultKaxisBcJcaGenerator.spawn(algParameter)
    assertNotNull(jcaMiscPemGroove)

    val caGroove = jcaMiscPemGroove.caGroove
    val serverGroove = jcaMiscPemGroove.serverGroove
    val clientGroove = jcaMiscPemGroove.clientGroove

    assertNotNull(caGroove)
    assertNotNull(serverGroove)
    assertNotNull(clientGroove)

    executorService.submit {
      try {
        startDtlsServer(caGroove, serverGroove)
      } catch (e: IOException) {
        throw RuntimeException(e)
      }
    }
    TimeUnit.MILLISECONDS.sleep(200L)

    executorService.submit {
      try {
        startDtlsClient(caGroove, clientGroove)
      } catch (e: IOException) {
        throw RuntimeException(e)
      }
    }

    Awaitility.await().atMost(Duration.ofSeconds(10L)).untilAsserted {
      assertTrue { isHandshakeFinish.compareAndSet(true, false) }
    }
  }

  @Throws(IOException::class)
  fun startDtlsClient(
    caGroove: KaxisBcFabric.JcaKeyPair,
    clientGroove: KaxisBcFabric.JcaKeyPair,
  ) {
    val address = InetAddress.getByName(null)
    val client = MockDtlsClient(caGroove, clientGroove)
    val dtls = openDtlsConnection(address, client)

    println("Receive limit: ${dtls.receiveLimit}")
    println("Send limit: ${dtls.sendLimit}")

    // Send and hopefully receive a packet back
    val request = "Hello World!\n".toByteArray()
    dtls.send(request, 0, request.size)

    val response = ByteArray(dtls.receiveLimit)
    val received = dtls.receive(response, 0, response.size, 30_000)
    if (received >= 0) {
      println("[client] Receive: ${String(response, 0, received, StandardCharsets.UTF_8)}")
    }
    dtls.close()
    isHandshakeFinish.compareAndSet(false, true)
  }

  private fun openDtlsConnection(
    address: InetAddress,
    client: TlsClient,
  ): DTLSTransport {
    val socket = DatagramSocket()
    socket.connect(address, PORT)
    val transport = UDPTransport(socket, MTU)
    val protocol = DTLSClientProtocol()
    return protocol.connect(client, transport)
  }

  @Throws(IOException::class)
  private fun startDtlsServer(
    caGroove: KaxisBcFabric.JcaKeyPair,
    serverGroove: KaxisBcFabric.JcaKeyPair,
  ) {
    val verifier = DTLSVerifier(BcTlsCrypto(SecureRandom()))
    var request: DTLSRequest?
    val data = ByteArray(MTU)
    val packet = DatagramPacket(data, MTU)
    val socket = DatagramSocket(PORT)

    // Process incoming packets, replying with HelloVerifyRequest, until one is verified.
    do {
      socket.receive(packet)
      request =
        verifier.verifyRequest(
          packet.address.address,
          data,
          0,
          packet.length,
          object : DatagramSender {
            override fun getSendLimit(): Int = MTU - 28

            override fun send(
              buf: ByteArray?,
              off: Int,
              len: Int,
            ) {
              if (len > sendLimit) {
                throw TlsFatalAlert(AlertDescription.internal_error)
              }
              socket.send(DatagramPacket(buf, off, len, packet.address, packet.port))
            }
          },
        )
    } while (request == null)
    // Proceed to a handshake, passing verified 'request' (ClientHello) to DTLSServerProtocol.accept.
    println(
      "Accepting connection from ${Highlight.BLUE}${packet.address.hostAddress}:${packet.port}${Highlight.RESET}",
    )
    socket.connect(packet.address, packet.port)
    val transport = UDPTransport(socket, MTU)
    val server = MockDtlsServer(caGroove, serverGroove)
    val serverProtocol = DTLSServerProtocol()
    val dtlsServer = serverProtocol.accept(server, transport, request)
    val buf = ByteArray(dtlsServer.receiveLimit)
    while (!socket.isClosed) {
      try {
        val length = dtlsServer.receive(buf, 0, buf.size, 60_000)
        if (length >= 0) {
          print("[Server] Receive: ")
          System.out.write(buf, 0, length)
          println()
          dtlsServer.send(buf, 0, length)
        }
      } catch (_: SocketTimeoutException) {
      }
      dtlsServer.close()
    }
  }

  inner class MockDtlsClient(
    private val caGroove: KaxisBcFabric.JcaKeyPair,
    private val clientGroove: KaxisBcFabric.JcaKeyPair,
  ) : AbstractDtlsClient() {
    override fun getClientCaCert(): Certificate = caGroove.getTlsX509Certificate(context.crypto as BcTlsCrypto)

    override fun getClientPrivateKey(): AsymmetricKeyParameter {
      try {
        return clientGroove.cryptoPrivateAsymmetricKey
      } catch (e: InvalidKeySpecException) {
        logger.error("fail to read client_key")
        throw TlsFatalAlert(AlertDescription.unknown_psk_identity, e)
      }
    }

    override fun getClientCert(): Certificate = clientGroove.getTlsX509Certificate(context.crypto as BcTlsCrypto)
  }

  inner class MockDtlsServer(
    private val caGroove: KaxisBcFabric.JcaKeyPair,
    private val serverGroove: KaxisBcFabric.JcaKeyPair,
  ) : AbstractDtlsServer() {
    override fun getServerCaCert(): Certificate = caGroove.getTlsX509Certificate(context.crypto as BcTlsCrypto)

    override fun getServerPrivateKey(): AsymmetricKeyParameter {
      try {
        return serverGroove.cryptoPrivateAsymmetricKey
      } catch (e: InvalidKeySpecException) {
        logger.error("fail to read server_key")
        throw TlsFatalAlert(AlertDescription.unknown_psk_identity, e)
      }
    }

    override fun getServerCert(): Certificate = serverGroove.getTlsX509Certificate(context.crypto as BcTlsCrypto)
  }
}
