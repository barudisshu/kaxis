/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.handler

import io.kaxis.Bytes
import io.kaxis.auth.PreSharedKeyIdentity
import io.kaxis.auth.RawPublicKeyIdentity
import io.kaxis.auth.X509CertPath
import io.kaxis.config.CertificateAuthenticationMode
import io.kaxis.delegates.NullableDelegates
import io.kaxis.dtls.*
import io.kaxis.dtls.cipher.*
import io.kaxis.dtls.extensions.*
import io.kaxis.dtls.message.AlertMessage
import io.kaxis.dtls.message.ChangeCipherSpecMessage
import io.kaxis.dtls.message.FragmentedHandshakeMessage
import io.kaxis.dtls.message.HandshakeMessage
import io.kaxis.dtls.message.handshake.*
import io.kaxis.dtls.pskstore.AdvancedMultiPskStore
import io.kaxis.dtls.pskstore.AdvancedPskStore
import io.kaxis.dtls.x509.CertificateProvider
import io.kaxis.dtls.x509.NewAdvancedCertificateVerifier
import io.kaxis.dtls.x509.provider.SingleCertificateProvider
import io.kaxis.dtls.x509.verifier.StaticNewAdvancedCertificateVerifier
import io.kaxis.exception.HandshakeException
import io.kaxis.fsm.ClientHelloRequest
import io.kaxis.fsm.Command
import io.kaxis.fsm.Recipient
import io.kaxis.fsm.State
import io.kaxis.result.CertificateIdentityResult
import io.kaxis.result.PskSecretResult
import io.kaxis.util.*
import org.apache.pekko.actor.typed.ActorRef
import org.apache.pekko.actor.typed.javadsl.ActorContext
import org.apache.pekko.persistence.typed.state.javadsl.EffectFactories
import org.apache.pekko.persistence.typed.state.javadsl.ReplyEffect
import org.slf4j.Logger
import java.net.DatagramPacket
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.concurrent.LinkedTransferQueue
import java.util.concurrent.atomic.AtomicReference
import java.util.function.BiFunction
import javax.crypto.SecretKey
import javax.security.auth.x500.X500Principal

/**
 * Server handshaker does the protocol handshaking from the point of view of a server. It is message-driven flow
 * depicted in [Figure 1](https://tools.ietf.org/html/rfc6347#page-21).
 *
 * ```
 *   Client                                          Server
 *   ------                                          ------
 *
 *   ClientHello             -------->                           Flight 1
 *
 *                           <--------   HelloVerifyRequest      Flight 2
 *
 *   ClientHello             -------->                           Flight 3
 *
 *                                              ServerHello    \
 *                                             Certificate*     \
 *                                       ServerKeyExchange*      Flight 4
 *                                      CertificateRequest*     /
 *                           <--------      ServerHelloDone    /
 *
 *   Certificate*                                              \
 *   ClientKeyExchange                                          \
 *   CertificateVerify*                                          Flight 5
 *   [ChangeCipherSpec]                                         /
 *   Finished                -------->                         /
 *
 *                                       [ChangeCipherSpec]    \ Flight 6
 *                           <--------             Finished    /
 * ```
 *
 * Actually, TLS parameters is a mess!!. Propagate its properties here.
 * @author galudisu
 */
abstract class StageBiFunction<C, R, D>(
  context: ActorContext<C>,
  val effect: EffectFactories<State>,
) : BiFunction<State, R, ReplyEffect<State>>,
  StageHandler<R> where C : Command, R : Recipient<D>, D : DTLSMessage {
  val log: Logger = context.log
  val self: ActorRef<C> = context.self
  private lateinit var state: State
  lateinit var cmd: R

  open val message: D by NullableDelegates { cmd.message }

  open val decodedRecord: Record by NullableDelegates { cmd.decodedRecord }

  /**
   * Mark connection to require an abbreviated handshake.
   *
   * Used to know when an abbreviated handshake should be initiated.
   */
  var resumptionRequired: Boolean
    get() = state.resumptionRequired
    set(value) {
      state.resumptionRequired = value
    }

  // Use peer-address for handshake.
  val peerAddress: InetSocketAddress by NullableDelegates { state.peerAddress }

  val ipv6: Boolean by NullableDelegates { peerAddress.address is Inet6Address }

  val peerToLog: Any by NullableDelegates { Utility.toLog(peerAddress) }

  fun initializePeerAddress(peerAddress: InetSocketAddress?) {
    if (state.peerAddress == null) {
      requireNotNull(peerAddress) { "the DTLS client's InetSocketAddress must be present!" }
      state.peerAddress = peerAddress
    }
  }

  // Once handshake established, use cid for data transform.
  // And peerAddress will set to null after connection is established.
  val cid: ConnectionId by NullableDelegates { state.cid }

  fun initializeCid(cid: ConnectionId?) {
    if (state.cid == null) {
      requireNotNull(cid) { "the Connection ID must be present!" }
      state.cid = cid
    }
  }

  // DTLS context for encrypted and decrypted. Must be serialized
  val dtlsContext: DTLSContext by NullableDelegates { state.dtlsContext }

  fun initializeDtlsContext(dtlsContext: DTLSContext?) {
    if (state.dtlsContext == null) {
      requireNotNull(dtlsContext) { "the DTLSContext must be present!" }
      state.dtlsContext = dtlsContext
    }
  }

  val session: DTLSSession
    get() = dtlsContext.session

  val serverNames: ServerNames?
    get() = if (sniEnabled) session.serverNames else null

  // mark the field like this to ignore it during de/serialization
  // for security issue, SecureRandom will not be persisted.
  val idGenerator: ConnectionIdGenerator
    get() = state.idGenerator

  val cookieGenerator: CookieGenerator
    get() = state.cookieGenerator

  /**
   * The handshaker's certificate identity provider.
   */
  val certificateIdentityProvider: CertificateProvider?
    get() {
      val serverCredentials0: SslContextUtil.Credentials? = serverCredentials
      return if (serverCredentials0 != null) {
        SingleCertificateProvider(
          serverCredentials0.privateKey,
          serverCredentials0.certificateChain.toMutableList().toTypedArray(),
          mutableListOf(
            CertificateType.RAW_PUBLIC_KEY,
            CertificateType.X_509,
          ),
        )
      } else {
        null
      }
    }

  val advancedPskStore: AdvancedPskStore
    get() {
      val pskStore = AdvancedMultiPskStore()
      // put in the PSK store the default identity/psk for tinydtls tests
      pskStore.setKey("Client_identity", "secretPSK".toByteArray())
      return pskStore
    }

  /**
   * The logic in charge of verifying the chain of certificates asserting this handshaker's identity.
   */
  val certificateVerifier: NewAdvancedCertificateVerifier?
    get() {
      return if (!trustedCertificates.isNullOrEmpty()) {
        StaticNewAdvancedCertificateVerifier
          .builder()
          .setTrustedCertificates(trustedCertificates)
          .setTrustAllRPKs()
          .build()
      } else {
        null
      }
    }

  // /////////////////////////////////////////////////////////////
  // TODO) refactor to actor handler

  var eccExpected: Boolean = false

  var changeCipherSuiteMessageExpected: Boolean = false

  var contextEstablished: Boolean = false

  var handshakeCompleted: Boolean = false

  var handshakeAborted: Boolean = false

  var handshakeFailed: Boolean = false

  var pskRequestPending: Boolean = false

  var certificateVerificationPending: Boolean = false

  var certificateIdentityPending: Boolean = false

  var certificateIdentityAvailable: Boolean = false

  // ////////////////

  private var ipv4Mtu: Int = NetworkInterfacesUtil.DEFAULT_IPV4_MTU
    get() {
      return if (maximumTransmissionUnit == null) {
        NetworkInterfacesUtil.ipv4Mtu
      } else {
        field
      }
    }

  private var ipv6Mtu: Int = NetworkInterfacesUtil.DEFAULT_IPV6_MTU
    get() {
      return if (maximumTransmissionUnit == null) {
        NetworkInterfacesUtil.ipv6Mtu
      } else {
        field
      }
    }

  /**
   * List of handshake messages.
   */
  @Volatile
  var handshakeMessages: LinkedTransferQueue<HandshakeMessage> = LinkedTransferQueue()

  /**
   * Current partial reassembled handshake message.
   */
  @Volatile
  var reassembledMessage: ReassemblingHandshakeMessage? = null

  lateinit var cipherSuiteParameters: CipherSuiteParameters

  /**
   * Pending client hello while requesting the certificate indentity.
   */
  var pendingClientHello: ClientHello? = null

  var pendingFlight: AtomicReference<DTLSFlight> = AtomicReference()

  var privateKey: PrivateKey? = null

  var publicKey: PublicKey? = null

  var certificateChain: MutableList<X509Certificate>? = null

  lateinit var clientRandom: Random

  lateinit var serverRandom: Random

  var certificateVerifyMessage: CertificateVerify? = null

  lateinit var preSharedKeyIdentity: PskPublicInformation

  lateinit var ecdhe: XECDHECryptography

  lateinit var masterSecretSeed: ByteArray

  var masterSecret: SecretKey? = null

  var clientWriteMACKey: SecretKey? = null
  var serverWriteMACKey: SecretKey? = null

  var clientWriteKey: SecretKey? = null
  var serverWriteKey: SecretKey? = null

  var clientWriteIV: SecretIvParameterSpec? = null
  var serverWriteIV: SecretIvParameterSpec? = null

  @Volatile
  var generateClusterMacKeys: Boolean = false

  var otherSecret: SecretKey? = null

  lateinit var identity: PskPublicInformation

  lateinit var secret: SecretKey

  var sendMessageSequence: Int = 1

  var flightNumber: Int = 1

  /**
   * Marks this handshaker to expect the peer's _CHANGE_CIPHER_SPEC_ message next.
   */
  fun expectChangeCipherSpecMessage() {
    this.changeCipherSuiteMessageExpected = true
  }

  /**
   * Marks this handshaker to expect the peer to calculate some ECC function. [additionalTimeoutForEcc]
   * will be added for the next flight in that case.
   */
  fun expectEcc() {
    this.eccExpected = true
  }

  override fun apply(
    state: State,
    cmd: R,
  ): ReplyEffect<State> {
    this.state = state
    this.cmd = cmd

    return handle(state, cmd)
  }

  /**
   * Generate [HelloVerifyRequest] from a [ClientHelloRequest].
   * @return empty byte array if it's already verified, or, a [HelloVerifyRequest]'s record.
   */
  fun generateHelloVerifyRequest(clientHello: ClientHello): Record? {
    val expectedCookie = cookieGenerator.generateCookie(peerAddress, clientHello)

    // before starting a new handshake or resuming an established
    // session we need to make sure that the peer is in possession of
    // the IP address indicated in the client hello message
    val addressVerify = isClientInControlOfSourceIpAddress(cmd.peerAddress, clientHello, expectedCookie)
    if (addressVerify) {
      // sender's address is yet verified
      // no need to send HELLO_VERIFY_REQUEST
      return null
    }

    // send CLIENT_HELLO_VERIFY with cookie in order to prevent
    // DOS attack as described in DTLS 1.2 spec
    log.trace("Verifying client IP address [{}] using HELLO_VERIFY_REQUEST", Utility.toLog(cmd.peerAddress))
    val version = protocolVersionForHelloVerifyRequests

    // according RFC 6347, 4.2.1. Denial-of-Service Countermeasures,
    // the HelloVerifyRequest should use version 1.0
    val helloVerifyRequest = HelloVerifyRequest(version, expectedCookie)
    // because we do not have a handshaker in place yet that
    // manages message_seq from CLIENT_HELLO in order to allow for
    // multiple consecutive(连续丢包) cookie exchanges with a client
    helloVerifyRequest.messageSeq = clientHello.messageSeq
    // use epoch 0 and sequence no from CLIENT_HELLO record as
    // mandated by section 4.2.1 of the DTLS 1.2 spec
    // see http://tools.ietf.org/html/rfc6347#section-4.2.1

    // actually, the handshake sequence number is in the range [0..65535] Int.MAX_VALUE.
    // but [Record]'s seq will be very large, so mark as Long.MAX_VALUE.
    val helloVerify = Record(ContentType.HANDSHAKE, version, clientHello.messageSeq.toLong(), helloVerifyRequest)
    helloVerify.peerAddress = cmd.peerAddress

    return helloVerify
  }

  /**
   * Checks whether the peer is able to receive data on the IP address indicated in its client hello message.
   * The check is done by means of comparing the cookie contained in the client hello message with the cookie
   * computed for the request using the `generateCookie` method.
   *
   * If a matching session id is contained, but no cookie, it depends on the number of pending resumption
   * handshakes, if a _HELLO_VERIFY_REQUEST_ is sent to the peer, of a resumption handshake is started without.
   *
   * **NOTE**: it is not recommended to disable the _HELLO_VERIFY_REQUEST_!
   * See [RFC 6347, 4.2.1. Denial-of-Service Countermeasures](https://tools.ietf.org/html/rfc6347#section-4.2.1).
   *
   * @param peerAddress the inet socket address to verify
   * @param clientHello the peer's client hello method including the cookie and/or session id to verify
   * @param expectedCookie expected cookie
   *
   * @return `true`, if the cookie is matching, or, if absent, the session id is valid, `false`, if either the
   * cookie is not matching, or, if absent, the session id is invalid.
   */
  private fun isClientInControlOfSourceIpAddress(
    peerAddress: InetSocketAddress,
    clientHello: ClientHello,
    expectedCookie: ByteArray,
  ): Boolean {
    // verify client's ability to respond on given IP address by exchanging
    // a cookie as described in section 4.2.1 of the DTLS 1.2 spec
    // see http://tools.ietf.org/html/rfc6347#section-4.2.1
    val providedCookie = clientHello.cookie

    if (providedCookie != null && providedCookie.isNotEmpty()) {
      // check, if cookie of the current period matches
      var cookie = MessageDigest.isEqual(expectedCookie, providedCookie)
      if (!cookie) {
        try {
          // check, if cookie of the past period matches
          val pastCookie = cookieGenerator.generatePastCookie(peerAddress, clientHello)
          if (pastCookie != null && MessageDigest.isEqual(pastCookie, providedCookie)) {
            cookie = true
          }
        } catch (ex: GeneralSecurityException) {
          log.debug("failed to generate past cookie", ex)
        }
      }
      if (!cookie) {
        log.debug(
          "provided cookie must {} match {}. Send verify request to {}",
          Utility.byteArray2HexString(providedCookie, Utility.NO_SEPARATOR, 6),
          Utility.byteArray2HexString(expectedCookie, Utility.NO_SEPARATOR, 6),
          Utility.toLog(peerAddress),
        )
      }
      return cookie
    }

    return false
  }

  /**
   * Negotiates the version to be used. It will return the lowest of that suggested by the client in the client
   * hello and the highest supported by the server.
   * @param clientVersion the suggested version by the client.
   * @return the version to be used in the handshake.
   * @throws HandshakeException if the client's version is smaller than DTLS 1.2.
   */
  @Throws(HandshakeException::class)
  fun negotiateProtocolVersion(clientVersion: ProtocolVersion): ProtocolVersion =
    if (clientVersion >= ProtocolVersion.VERSION_DTLS_1_2) {
      ProtocolVersion.VERSION_DTLS_1_2
    } else {
      var version = clientVersion
      if (version < ProtocolVersion.VERSION_DTLS_1_0) {
        version = ProtocolVersion.VERSION_DTLS_1_0
      }
      val alert = AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.PROTOCOL_VERSION, version)
      throw HandshakeException(alert, "The server only supports DTLS 1.2, not $clientVersion!")
    }

  /**
   * Selects one of the client's proposed cipher suites.
   *
   * Delegates the selection calling [CipherSuiteSelector.select].
   *
   * @param clientHello the _CLIENT_HELLO_ message.
   * @throws HandshakeException if this server's configuration does not support any of the cipher suites
   * proposed by the client.
   * @see CipherSuiteSelector
   * @see DefaultCipherSuiteSelector
   */
  @Suppress("kotlin:S3776")
  @Throws(HandshakeException::class)
  fun negotiateCipherSuite(clientHello: ClientHello?) {
    log.trace("Negotiate on: {}", cipherSuiteParameters)
    if (cipherSuiteSelector.select(cipherSuiteParameters)) {
      log.debug("Negotiated: {}", cipherSuiteParameters)
      val session = dtlsContext.session
      val cipherSuite = cipherSuiteParameters.selectedCipherSuite
      requireNotNull(cipherSuite) { "Negotiated cipher suite must not be null!" }
      session.cipherSuite = cipherSuite
      if (cipherSuite.requiresServerCertificateMessage) {
        session.signatureAndHashAlgorithm = cipherSuiteParameters.selectedSignature
        var certificateType = cipherSuiteParameters.selectedServerCertificateType
        if (certificateType == null) {
          val alert = AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.UNSUPPORTED_CERTIFICATE)
          throw HandshakeException(alert, "No common server certificate type!")
        }
        session.sendCertificateType = certificateType
        certificateType = cipherSuiteParameters.selectedClientCertificateType
        if (CertificateAuthenticationMode.NEEDED == clientAuthenticationMode) {
          if (certificateType == null) {
            val alert =
              AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.UNSUPPORTED_CERTIFICATE)
            throw HandshakeException(alert, "No common client certificate type!")
          }
          session.receiveCertificateType = certificateType
        } else if (CertificateAuthenticationMode.WANTED == clientAuthenticationMode) {
          if (certificateType != null) {
            session.receiveCertificateType = certificateType
          }
          // if no common certificate type is available,
          // keep X.509 but don't send the extension
        }
      }
      log.debug("Negotiated cipher suite [{}] with peer [{}]", cipherSuite.name, Utility.toLog(peerAddress))
    } else {
      if (log.isDebugEnabled) {
        log.debug("{}", clientHello)
        log.debug("{}", cipherSuiteParameters.mismatchDescription)
        log.trace("Parameters: {}", cipherSuiteParameters)
      }
      var summary = cipherSuiteParameters.mismatchSummary
      if (summary == null) {
        summary = "Client proposed unsupported cipher suites or parameters only"
      }
      // cleanup if failure
      // this.cipherSuiteParameters = null
      // if none of the client's proposed cipher suites matches throw
      val alert = AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.HANDSHAKE_FAILURE)
      throw HandshakeException(alert, summary)
    }
  }

  /**
   * Determines the elliptic curve to use during the EC based DH key exchange.
   *
   * @param clientCurves the peer's extension containing its preferred elliptic curves
   *
   * @return a list of commonly supported curves. Maybe empty if server and client have no curves in common
   *
   */
  fun getCommonSupportedGroups(
    clientCurves: SupportedEllipticCurvesExtension?,
  ): MutableList<XECDHECryptography.SupportedGroup> {
    val groups = arrayListOf<XECDHECryptography.SupportedGroup>()
    if (clientCurves == null) {
      // according to RFC 4492, section 4
      // (https://tools.ietf.org/html/rfc4492#section-4)
      // we are free to pick any curve in this case
      groups.addAll(supportedGroups)
    } else {
      clientCurves.supportedGroups.forEach { group ->
        // use first group proposed by client contained in list of
        // server's preferred groups
        if (supportedGroups.contains(group)) {
          groups.add(group)
        }
      }
    }
    return groups
  }

  fun negotiateECPointFormat(
    clientPointFormats: SupportedPointFormatsExtension?,
  ): SupportedPointFormatsExtension.ECPointFormat? =
    if (clientPointFormats == null) {
      // according to RFC 4492, section 4
      // (https://tools.ietf.org/html/rfc4492#section-4)
      // we are free to pick any format in this case
      SupportedPointFormatsExtension.ECPointFormat.UNCOMPRESSED
    } else if (clientPointFormats.contains(SupportedPointFormatsExtension.ECPointFormat.UNCOMPRESSED)) {
      SupportedPointFormatsExtension.ECPointFormat.UNCOMPRESSED
    } else {
      null
    }

  /**
   * Determines the signature and hash algorithm to use during the EC based handshake.
   *
   * @param clientSignatureAndHashAlgorithms the peer's extension containing its preferred
   * signatures and hash algorithms
   *
   * @return a list of common signatures and hash algorithms. Maybe empty if server and client have no
   * signature and hash algorithm in common
   */
  fun getCommonSignatureAndHashAlgorithms(
    clientSignatureAndHashAlgorithms: SignatureAlgorithmsExtension?,
  ): MutableList<SignatureAndHashAlgorithm> =
    if (clientSignatureAndHashAlgorithms == null) {
      ArrayList(supportedSignatureAndHashAlgorithms)
    } else {
      SignatureAndHashAlgorithm.getCommonSignatureAlgorithms(
        clientSignatureAndHashAlgorithms.signatureAndHashAlgorithms,
        supportedSignatureAndHashAlgorithms,
      )
    }

  fun getCommonCipherSuites(clientHello: ClientHello): MutableList<CipherSuite> {
    var supported = supportedCipherSuites
    val sessionCipherSuite = dtlsContext.session.cipherSuite
    if (sessionCipherSuite.isValidForNegotiation) {
      // resumption, limit handshake to use the same cipher suite
      supported = arrayListOf(sessionCipherSuite)
    }
    return CipherSuite.preselectCipherSuites(supported, clientHello.cipherSuites)
  }

  fun getCommonClientCertificateTypes(
    clientCertificateTypeExtension: ClientCertificateTypeExtension?,
  ): MutableList<CertificateType> {
    var supported = supportedClientCertificateTypes
    val principal = dtlsContext.session.peerIdentity
    if (principal != null) {
      // resumption, reconstruct the certificate type
      // including into SessionTicket requires a major release
      supported = arrayListOf()
      if (principal is RawPublicKeyIdentity) {
        supported.add(CertificateType.RAW_PUBLIC_KEY)
      } else if (principal is X509CertPath) {
        supported.add(CertificateType.X_509)
      }
    }
    return getCommonCertificateTypes(clientCertificateTypeExtension, supported)
  }

  /**
   * Get a list of common supported certificate types if the extension is available, used it to find a supported
   * certificate type. If the extension is not available, check if X.509 is supported.
   *
   * @param certTypeExt certificate type extension, `null`, if not available.
   * @param supportedCertificateTypes supported certificate types of peer.
   * @return list of commonly supported certificate types. Empty, if no common certificate type could be found.
   */
  fun getCommonCertificateTypes(
    certTypeExt: CertificateTypeExtension?,
    supportedCertificateTypes: MutableList<CertificateType>?,
  ): MutableList<CertificateType> {
    if (supportedCertificateTypes != null) {
      if (certTypeExt != null) {
        return certTypeExt.getCommonCertificateTypes(supportedCertificateTypes)
      } else if (supportedCertificateTypes.contains(CertificateType.X_509)) {
        return CertificateTypeExtension.DEFAULT_X509
      }
    }
    return CertificateTypeExtension.EMPTY
  }

  fun getCommonServerCertificateTypes(
    serverCertificateTypes: ServerCertificateTypeExtension?,
  ): MutableList<CertificateType> = getCommonCertificateTypes(serverCertificateTypes, supportedServerCertificateTypes)

  /**
   * Called after the server receives a [ClientHello] handshake message. Determines common security
   * parameters and prepares to create the response.
   *
   * If a certificate-based cipher suite is shared, request the certificate identity calls [processClientHello]
   * on available certificate identity.
   *
   * @param clientHello the client's hello message.
   * @throws HandshakeException if the server's response message(s) cannot be created
   */
  @Suppress("kotlin:S3776")
  @Throws(HandshakeException::class)
  fun receivedClientHello(clientHello: ClientHello) {
    negotiateProtocolVersion(clientHello.protocolVersion)

    if (!clientHello.compressionMethods.contains(CompressionMethod.NULL)) {
      // abort handshake
      throw HandshakeException(
        AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.HANDSHAKE_FAILURE),
        "Client does not support NULL compression method",
      )
    }

    var commonCipherSuites = getCommonCipherSuites(clientHello)
    if (commonCipherSuites.isEmpty()) {
      log.trace("Server cipher suites: {}", supportedCipherSuites)
      // abort handshake
      throw HandshakeException(
        AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.HANDSHAKE_FAILURE),
        "Client does not propose a common cipher suite",
      )
    }
    if (useHelloVerifyRequest && !clientHello.hasCookie) {
      val sessionId = session.sessionIdentifier
      if (sessionId.isEmpty() || sessionId != clientHello.sessionId) {
        // no cookie, no resumption => only PSK reduce amplification
        val common: MutableList<CipherSuite> = arrayListOf()
        commonCipherSuites.forEach { cipherSuite ->
          if (cipherSuite.isPskBased) {
            common.add(cipherSuite)
          }
        }
        commonCipherSuites = common
      }
    }
    val commonServerCertTypes = getCommonServerCertificateTypes(clientHello.serverCertificateTypeExtension)
    val commonClientCertTypes = getCommonClientCertificateTypes(clientHello.clientCertificateTypeExtension)
    val commonGroups = getCommonSupportedGroups(clientHello.supportedEllipticCurvesExtension)
    val commonSignatures = getCommonSignatureAndHashAlgorithms(clientHello.supportedSignatureAlgorithmsExtension)
    val format = negotiateECPointFormat(clientHello.supportedPointFormatsExtension)

    val serverNameExt = clientHello.serverNameExtension
    if (serverNameExt != null) {
      if (sniEnabled) {
        // store the names indicated by peer for later reference during
        // key exchange
        session.serverNames = serverNameExt.serverNames
        session.peerSupportsSni = true
        log.debug("using server name indication received from peer [{}]", peerToLog)
      } else {
        log.debug("client [{}] included SNi in HELLO but SNI support is disabled", peerToLog)
      }
    }

    this.cipherSuiteParameters =
      CipherSuiteParameters(
        clientAuthenticationMode = clientAuthenticationMode,
        cipherSuites = commonCipherSuites,
        serverCertTypes = commonServerCertTypes,
        clientCertTypes = commonClientCertTypes,
        supportedGroups = commonGroups,
        signatures = commonSignatures,
        format = format,
      )

    log.debug("peer [{}] was assembly cipher suite parameters: \n{}", peerToLog, this.cipherSuiteParameters)

    if (CipherSuite.containsCipherSuiteRequiringCertExchange(commonCipherSuites)) {
      this.pendingClientHello = clientHello
      val serverNames = serverNames
      val keyAlgorithms = CipherSuite.getCertificateKeyAlgorithms(commonCipherSuites)
      if (requestCertificateIdentity(null, serverNames, keyAlgorithms, commonSignatures, commonGroups)) {
//        startInitialTimeout()
      }
    } else {
      processClientHello(clientHello)
    }
  }

  /**
   * Request the certificate-based identity.
   *
   * @param issuers list of trusted issuers. May be `null` or empty.
   * @param serverNames indicated server names. May be `null` or empty.
   * @param certificateKeyAlgorithms list of certificate key algorithms to select a node's certificate. May be `null` or empty.
   * @param signatureAndHashAlgorithms list of supported signatures and hash algorithms. May be `null` or empty.
   * @param curves ec-curves (supported groups). May be `null` or empty.
   *
   * @return `true`, if the certificate-based identity is available, `false`, if the certificate-based identity is requested.
   * @throws HandshakeException if any of the checks fails
   */
  @Throws(HandshakeException::class)
  fun requestCertificateIdentity(
    issuers: MutableList<X500Principal>?,
    serverNames: ServerNames?,
    certificateKeyAlgorithms: MutableList<CipherSuite.CertificateKeyAlgorithm>?,
    signatureAndHashAlgorithms: MutableList<SignatureAndHashAlgorithm>?,
    curves: MutableList<XECDHECryptography.SupportedGroup>?,
  ): Boolean {
    certificateIdentityPending = true
    val result =
      if (certificateIdentityProvider == null) {
        CertificateIdentityResult(cid)
      } else {
        log.info("Start certificate identity.")
        certificateIdentityProvider?.requestCertificateIdentity(
          cid,
          false,
          issuers,
          serverNames,
          certificateKeyAlgorithms,
          signatureAndHashAlgorithms,
          curves,
        )
      }
    return if (result != null) {
      processCertificateIdentityResult(result)
      false
    } else {
      true
    }
  }

  /**
   * Process the certificate identity.
   *
   * @param result certificate identity
   * @throws HandshakeException if an error occurs
   * @throws IllegalStateException if no call is pending (see [certificateIdentityPending]), or the handshaker [isDestroyed]
   */
  @Throws(HandshakeException::class)
  fun processCertificateIdentityResult(result: CertificateIdentityResult) {
    check(certificateIdentityPending) { "certificate identity not pending!" }
    certificateIdentityPending = false
    log.debug("Process result of certificate identity.")
    this.privateKey = result.privateKey
    this.publicKey = result.publicKey
    this.certificateChain = result.certificateChain
    this.certificateIdentityAvailable = true
    processCertificateIdentityAvailable()
  }

  /**
   * Do the handshaker specific processing of certificate identity.
   *
   * Amend the certificate identity to the security parameter and continue the processing of
   * the client hello.
   */
  @Throws(HandshakeException::class)
  fun processCertificateIdentityAvailable() {
    cipherSuiteParameters = CipherSuiteParameters(publicKey, certificateChain, cipherSuiteParameters)

    if (pendingClientHello != null) {
      val clientHello = pendingClientHello!!
      pendingClientHello = null
      processClientHello(clientHello)
    }
  }

  /**
   * Process client hello.
   * @param clientHello the _CLIENT_HELLO_ message.
   * @throws HandshakeException if the server's response message(s) cannot be created.
   */
  @Throws(HandshakeException::class)
  fun processClientHello(clientHello: ClientHello) {
    negotiateCipherSuite(clientHello)

    flightNumber = if (clientHello.hasCookie) 4 else 2

    val flight = createFlight()

    createServerHello(clientHello, flight)

    createCertificateMessage(flight)

    createServerKeyExchange(flight)

    val clientCertificate = createCertificateRequest(flight)
    // marked client certificate optional??

    /**
     * Last, send ServerHelloDone (mandatory)
     */
    val serverHelloDone = ServerHelloDone()
    wrapMessage(flight, serverHelloDone)

    this.pendingFlight.set(flight)
  }

  fun generateFragmentFromPendingFlight(): MutableList<DatagramPacket> {
    val flight = this.pendingFlight.get()
    val maxDatagramSize = getMaxDatagramSize(ipv6)
    val maxFragmentSize = session.effectiveFragmentLimit
    val datagrams =
      flight.getDatagrams(
        maxDatagramSize,
        maxFragmentSize,
        useMultiHandshakeMessageRecords,
        useMultiRecordMessages,
        false,
      )

    log.trace(
      "Sending flight of {} message(s) to peer [{}] using {} datagram(s) of max. {} bytes.",
      flight.numberOfMessages,
      peerToLog,
      datagrams.size,
      maxDatagramSize,
    )

    return datagrams
  }

  @Throws(HandshakeException::class)
  private fun createServerHello(
    clientHello: ClientHello,
    flight: DTLSFlight,
  ) {
    negotiateCipherSuite(clientHello)
    val serverVersion = negotiateProtocolVersion(clientHello.protocolVersion)
    // store client and server random
    this.clientRandom = clientHello.random

    val session = dtlsContext.session
    var useSessionId = this.useSessionId
    if (extendedMasterSecretMode.equals(ExtendedMasterSecretMode.ENABLED) &&
      !clientHello.hasExtendedMasterSecretExtension
    ) {
      useSessionId = false
    }

    val sessionId = if (useSessionId) SessionId() else SessionId.emptySessionId()
    session.sessionIdentifier = sessionId
    session.protocolVersion = serverVersion
    session.compressionMethod = CompressionMethod.NULL

    val serverHello = ServerHello(serverVersion, sessionId, session.cipherSuite, session.compressionMethod)

    addHelloExtensions(clientHello, serverHello)

    if (serverHello.cipherSuite.isEccBase) {
      expectEcc()
    }

    wrapMessage(flight, serverHello)
    serverRandom = serverHello.random
  }

  private fun createCertificateMessage(flight: DTLSFlight) {
    if (session.cipherSuite.requiresServerCertificateMessage) {
      val certificateMessage =
        when (val certificateType = session.sendCertificateType) {
          CertificateType.RAW_PUBLIC_KEY -> {
            CertificateMessage(cipherSuiteParameters.publicKey)
          }

          CertificateType.X_509 -> {
            CertificateMessage(cipherSuiteParameters.certificateChain)
          }

          else -> throw IllegalArgumentException("Certificate type $certificateType not supported")
        }
      wrapMessage(flight, certificateMessage)
    }
  }

  @Throws(HandshakeException::class)
  private fun createServerKeyExchange(flight: DTLSFlight) {
    /*
     * Third, send ServerKeyExchange (if required by key exchange algorithm)
     */
    val keyExchangeAlgorithm = session.keyExchange

    if (CipherSuite.KeyExchangeAlgorithm.ECDHE_PSK == keyExchangeAlgorithm ||
      CipherSuite.KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN == keyExchangeAlgorithm
    ) {
      try {
        val ecGroup = cipherSuiteParameters.selectedSupportedGroup
        requireNotNull(ecGroup) { "selected support not been calculate!" }
        ecdhe = XECDHECryptography(ecGroup)
      } catch (ex: GeneralSecurityException) {
        val alert = AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.ILLEGAL_PARAMETER)
        throw HandshakeException(alert, "Cannot process handshake message, caused by ${ex.message}", ex)
      }
    }

    var serverKeyExchange: ServerKeyExchange? = null
    when (keyExchangeAlgorithm) {
      CipherSuite.KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN -> {
        serverKeyExchange =
          EcdhSignedServerKeyExchange(
            session.signatureAndHashAlgorithm,
            ecdhe,
            privateKey,
            clientRandom,
            serverRandom,
          )
      }

      CipherSuite.KeyExchangeAlgorithm.PSK -> {
        /*
         * If the identity is based on the domain name, servers SHOULD NOT
         * send an identity hint and clients MUST ignore it. Are there use
         * cases that different PSKs are used for different actions or time
         * periods? How to configure the hint then?
         */
      }

      CipherSuite.KeyExchangeAlgorithm.ECDHE_PSK -> {
        serverKeyExchange = EcdhPskServerKeyExchange(PskPublicInformation.EMPTY, ecdhe)
      }

      else -> {
        // NULL does not require the server's key exchange message
      }
    }
    if (serverKeyExchange != null) {
      wrapMessage(flight, serverKeyExchange)
    }
  }

  private fun createCertificateRequest(flight: DTLSFlight): Boolean {
    val certificateType = session.receiveCertificateType
    if (clientAuthenticationMode.useCertificateRequest && session.cipherSuite.requiresServerCertificateMessage) {
      val certificateRequest = CertificateRequest()
      var signatures = supportedSignatureAndHashAlgorithms
      val keys = supportedCertificateKeyAlgorithms
      if (CertificateType.X_509 == certificateType) {
        certificateRequest.addSignatureAlgorithms(signatures)
        if (certificateVerifier != null) {
          certificateRequest.addCertificateAuthorities(certificateVerifier!!.acceptedIssuers)
        }
      } else if (CertificateType.RAW_PUBLIC_KEY == certificateType) {
        val algorithm = CipherSuite.CertificateKeyAlgorithm.getAlgorithm(publicKey)
        if (keys[0] != algorithm && keys.contains(algorithm) && algorithm != null) {
          // move own certificate key algorithm to preferred position
          keys.remove(algorithm)
          keys[0] = algorithm
        }
        signatures = SignatureAndHashAlgorithm.getCompatibleSignatureAlgorithms(signatures, keys)
        certificateRequest.addSignatureAlgorithms(signatures)
      }
      log.trace("Certificate Type: {}", certificateType)
      log.trace("Signature and hash algorithms {}/{}", signatures, supportedSignatureAndHashAlgorithms)
      log.trace("Certificate key algorithms {}/{}", keys, supportedCertificateKeyAlgorithms)
      keys.forEach { certificateKeyAlgorithm ->
        if (SignatureAndHashAlgorithm.isSupportedAlgorithm(signatures, certificateKeyAlgorithm)) {
          certificateRequest.addCertificateType(certificateKeyAlgorithm)
        }
      }
      wrapMessage(flight, certificateRequest)
      return true
    }
    return false
  }

  /**
   * Add server's hello extensions.
   *
   * @param clientHello the client hello message with the extensions proposed by the client.
   * @param serverHello the server hello message to add the common-supported extensions.
   * @throws HandshakeException if the client extension is in conflict with the server.
   *
   */
  @Suppress("kotlin:S3776")
  @Throws(HandshakeException::class)
  fun addHelloExtensions(
    clientHello: ClientHello,
    serverHello: ServerHello,
  ) {
    if (clientHello.hasExtendedMasterSecretExtension) {
      session.extendedMasterSecret = true
      serverHello.addExtension(ExtendedMasterSecretExtension.INSTANCE)
    }
    if (clientHello.hasRenegotiationInfo) {
      serverHello.addExtension(RenegotiationInfoExtension.INSTANCE)
      session.secureRenegotiation = true
    }
    if (session.cipherSuite.requiresServerCertificateMessage) {
      val certificateType = session.receiveCertificateType
      val certificateTypeExtension = clientHello.clientCertificateTypeExtension
      if (certificateTypeExtension != null && certificateTypeExtension.contains(certificateType)) {
        val ext = ClientCertificateTypeExtension(certificateType)
        serverHello.addExtension(ext)
      }
    }
    val certificateType = session.sendCertificateType
    val certificateTypeExtension = clientHello.serverCertificateTypeExtension
    if (certificateTypeExtension != null && certificateTypeExtension.contains(certificateType)) {
      val ext = ServerCertificateTypeExtension(certificateType)
      serverHello.addExtension(ext)
    }

    if (session.cipherSuite.isEccBase) {
      if (clientHello.supportedPointFormatsExtension != null) {
        // if we chose a ECC cipher suite, the server should send the
        // supported point formats extension in its ServerHello
        serverHello.addExtension(SupportedPointFormatsExtension.DEFAULT_POINT_FORMATS_EXTENSION)
      }
    }

    val recordSizeLimitExt = clientHello.recordSizeLimitExtension
    if (recordSizeLimitExt != null) {
      session.recordSizeLimit = recordSizeLimitExt.recordSizeLimit
      val limit = if (recordSizeLimit == 0) session.maxFragmentLength else recordSizeLimit
      serverHello.addExtension(RecordSizeLimitExtension(limit))
      log.debug("Received record size limit [{} bytes] from peer", limit)
    }

    if (recordSizeLimitExt == null) {
      val maxFragmentLengthExt = clientHello.maxFragmentLengthExtension
      if (maxFragmentLengthExt != null) {
        session.maxFragmentLength = maxFragmentLengthExt.fragmentLength.length
        serverHello.addExtension(maxFragmentLengthExt)
        log.debug(
          "Negotiated max. fragment length [{} bytes] with peer",
          maxFragmentLengthExt.fragmentLength.length,
        )
      }
    }

    val serverNameExt = clientHello.serverNameExtension
    if (serverNameExt != null) {
      // RFC 6066, section 3 requires the server to respond with
      // and empty SNI extension if it might make use of the value(s)
      // provided by the client
      serverHello.addExtension(ServerNameExtension.emptyServerNameIndication())
    }

    if (ConnectionId.supportsConnectionId(idGenerator)) {
      val connectionIdExtension = clientHello.connectionIdExtension
      if (connectionIdExtension != null) {
        val useDeprecatedCid = connectionIdExtension.useDeprecatedCid()
        if (!useDeprecatedCid) {
          val extension = ConnectionIdExtension.fromConnectionId(cid, connectionIdExtension.type)
          serverHello.addExtension(extension)
          dtlsContext.writeConnectionId = connectionIdExtension.connectionId
          dtlsContext.readConnectionId = cid
          dtlsContext.useDeprecatedCid = false
        }
      }
    }
  }

  /**
   * Crate new flight with the current [dtlsContext] and the current [flightNumber].
   */
  fun createFlight(): DTLSFlight = DTLSFlight(dtlsContext, flightNumber, peerAddress)

  /**
   * Request psk secret result for PSK cipher suites. Sets [pskRequestPending].
   *
   * @param pskIdentity PSK identity
   * @param otherSecret others secret for ECHDE support. Might be `null`.
   * @param seed seed to be used for (extended) master secret.
   * @throws HandshakeException if an error occurs
   * @throws NullPointerException if seed is `null`
   */
  @Throws(HandshakeException::class)
  fun requestPskSecretResult(
    pskIdentity: PskPublicInformation,
    otherSecret: SecretKey,
    seed: ByteArray?,
  ) {
    requireNotNull(seed) { "seed must not be null!" }
    val session0 = session
    val serverNames0 = serverNames
    val hmacAlgorithm = session0.cipherSuite.pseudoRandomFunctionMacName
    requireNotNull(hmacAlgorithm)
    pskRequestPending = true
    masterSecretSeed = seed
    this.otherSecret = SecretUtil.create(otherSecret)
    val result =
      advancedPskStore.requestPskSecretResult(
        cid,
        serverNames0,
        pskIdentity,
        hmacAlgorithm,
        otherSecret,
        masterSecretSeed,
        session.extendedMasterSecret,
      )
    if (result != null) {
      processPskSecretResult(result)
    }
  }

  /**
   * Process PSK secret result.
   * @param pskSecretResult PSK secret result.
   * @throws HandshakeException if an error occurs
   * @throws IllegalStateException if [pskRequestPending] is not pending, or the handshaker [isDestroyed]
   */
  @Throws(HandshakeException::class)
  fun processPskSecretResult(pskSecretResult: PskSecretResult) {
    check(pskRequestPending) { "psk secret not pending!" }
    pskRequestPending = false
    try {
      val session0 = session
      val hostName = if (sniEnabled) session0.hostName else null
      val pskIdentity = pskSecretResult.pskIdentity
      var newPskSecret = pskSecretResult.secret
      if (newPskSecret != null) {
        if (hostName != null) {
          log.trace("client [{}] uses PSK identity [{}] for server [{}]", peerToLog, pskIdentity, hostName)
        } else {
          log.trace("client [{}] uses PSK identity [{}]", peerToLog, pskIdentity)
        }
        val pskPrincipal: PreSharedKeyIdentity
        if (sniEnabled) {
          pskPrincipal = PreSharedKeyIdentity(hostName, pskIdentity.publicInfoAsString)
        } else {
          pskPrincipal = PreSharedKeyIdentity(pskIdentity.publicInfoAsString)
        }
        session0.peerIdentity = pskPrincipal
        if (PskSecretResult.ALGORITHM_PSK == newPskSecret.algorithm) {
          val hmac = session0.cipherSuite.threadLocalPseudoRandomFunctionMac
          requireNotNull(hmac)
          val premasterSecret = PseudoRandomFunction.generatePremasterSecretFromPSK(otherSecret, newPskSecret)
          val masterSecret =
            PseudoRandomFunction.generateMasterSecret(
              hmac,
              premasterSecret,
              masterSecretSeed,
              session0.extendedMasterSecret,
            )
          SecretUtil.destroy(premasterSecret)
          SecretUtil.destroy(newPskSecret)
          newPskSecret = masterSecret
        }
        applyMasterSecret(newPskSecret)
        SecretUtil.destroy(newPskSecret)
        processMasterSecret()
      } else {
        val alert = AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.UNKNOWN_PSK_IDENTITY)
        if (hostName != null) {
          throw HandshakeException(
            alert,
            "No pre-shared key found for [virtual host: $hostName, identity: $pskIdentity]",
          )
        } else {
          throw HandshakeException(alert, "No pre-shared key found for [identity: $pskIdentity]")
        }
      }
    } finally {
      SecretUtil.destroy(otherSecret)
      otherSecret = null
    }
  }

  fun processMasterSecret() {
    if (certificateVerifyMessage != null) {
      expectChangeCipherSpecMessage()
    }
  }

  /**
   * Applying the key expansion on the master secret generates a large key
   * block to generate the encryption, MAC and IV keys. Also set the master
   * secret to the session for later resumption handshakes.
   *
   * See [RFC 5246](https://tools.ietf.org/html/rfc5246#section-6.3) for further details about the keys.
   * @param masterSecret the master secret.
   * @see masterSecret
   * @see calculateKeys
   */
  fun applyMasterSecret(masterSecret: SecretKey) {
    this.masterSecret = SecretUtil.create(masterSecret)
    calculateKeys(masterSecret)
    session.masterSecret = masterSecret
  }

  /**
   * Resume master secret from established session.
   */
  fun resumeMasterSecret() {
    this.masterSecret = session.masterSecret
    calculateKeys(masterSecret)
  }

  /**
   * Calculates the encryption key, MAC key and IV from a given master secret.
   *
   * First, applies the key expansion to the master secret.
   */
  fun calculateKeys(masterSecret: SecretKey?) {
    /*
     * Create keys as suggested in
     * http://tools.ietf.org/html/rfc5246#section-6.3:
     * client_write_MAC_key[SecurityParameters.mac_key_length]
     * server_write_MAC_key[SecurityParameters.mac_key_length]
     * client_write_key[SecurityParameters.enc_key_length]
     * server_write_key[SecurityParameters.enc_key_length]
     * client_write_IV[SecurityParameters.fixed_iv_length]
     * server_write_IV[SecurityParameters.fixed_iv_length]
     *
     * To protect cluster internal forwarded and backwarded messages,
     * create two cluster key additionally with enc_key_length.
     *
     * client_cluster_MAC_key[SecurityParameters.enc_key_length]
     * server_cluster_MAC_key[SecurityParameters.enc_key_length]
     */
    val cipherSuite = dtlsContext.session.cipherSuite
    val macKeyLength = cipherSuite.macKeyLength
    val encKeyLength = cipherSuite.encKeyLength
    val fixedIvLength = cipherSuite.fixedIvLength
    val clusterMacKeyLength = if (generateClusterMacKeys) encKeyLength else 0
    val totalLength = (macKeyLength + encKeyLength + fixedIvLength + clusterMacKeyLength) * 2
    // See http://tools.ietf.org/html/rfc5246#section-6.3:
    //      key_block = PRF(SecurityParameters.master_secret, "key expansion",
    //                      SecurityParameters.server_random + SecurityParameters.client_random);
    val seed = Bytes.Companion.concatenate(serverRandom, clientRandom)
    val data =
      PseudoRandomFunction.doPRF(
        cipherSuite.threadLocalPseudoRandomFunctionMac!!,
        masterSecret!!,
        PseudoRandomFunction.Label.KEY_EXPANSION_LABEL,
        seed,
        totalLength,
      )
    var index = 0
    var length = macKeyLength
    clientWriteMACKey = SecretUtil.create(data, index, length, "Mac")
    index += length
    serverWriteMACKey = SecretUtil.create(data, index, length, "Mac")
    index += length

    length = encKeyLength
    clientWriteKey = SecretUtil.create(data, index, length, "AES")
    index += length
    serverWriteKey = SecretUtil.create(data, index, length, "AES")
    index += length

    length = fixedIvLength
    clientWriteIV = SecretUtil.createIv(data, index, length)
    index += length
    serverWriteIV = SecretUtil.createIv(data, index, length)

    if (generateClusterMacKeys) {
      length = clusterMacKeyLength
      val clusterClientMacKey = SecretUtil.create(data, index, length, "Mac")
      index += length
      val clusterServerMacKey = SecretUtil.create(data, index, length, "Mac")
      index += length

      // set it for server side.
      dtlsContext.setClusterMacKeys(clusterServerMacKey, clusterClientMacKey)
      SecretUtil.destroy(clusterClientMacKey)
      SecretUtil.destroy(clusterServerMacKey)
    }
    Bytes.clear(data)
    dtlsContext.setRandoms(clientRandom, serverRandom)
  }

  /**
   * While processing inbound-messages on a flight, invoke [setCurrentReadState] to calculate
   * the message sequences.
   *
   *
   */
  fun setCurrentReadState() {
    dtlsContext.createReadState(clientWriteKey, clientWriteIV, clientWriteMACKey)
  }

  /**
   * While processing outbound-messages on a flight, invoke [setCurrentWriteState] to calculate
   * the message sequences.
   */
  fun setCurrentWriteState() {
    dtlsContext.createWriteState(serverWriteKey, serverWriteIV, serverWriteMACKey)
  }

  /**
   * Create the [Finished] message for a pending handshake.
   *
   * @param handshakeHash the hash of the handshake messages
   * @return create `FINISHED` message
   */
  fun createFinishedMessage(handshakeHash: ByteArray) {
    val masterSecret0 = masterSecret
    val hmac = session.cipherSuite.threadLocalPseudoRandomFunctionMac
    checkNotNull(masterSecret0) { "master secret not available!" }
    checkNotNull(hmac) { "hmac not available!" }
    Finished(hmac, masterSecret0, false, handshakeHash)
  }

  /**
   * Verify the handshake hash of the `FINISHED`.
   *
   * @param finished received `FINISHED` message.
   * @param handshakeHash the hash of the handshake messages.
   * @throws HandshakeException if the data cannot be verified
   */
  @Throws(HandshakeException::class)
  fun verifyFinished(
    finished: Finished,
    handshakeHash: ByteArray,
  ) {
    val masterSecret0 = masterSecret
    val hmac = session.cipherSuite.threadLocalPseudoRandomFunctionMac
    checkNotNull(masterSecret0) { "master secret not available!" }
    checkNotNull(hmac) { "hmac not available!" }
    finished.verifyData(hmac, masterSecret0, true, handshakeHash)
  }

  /**
   * Checks, if the master secret is available.
   *
   * @return `true`, if available, `false`, otherwise.
   */
  fun hasMasterSecret(): Boolean = masterSecret != null

  /**
   * Add a handshake message to the flight. Assigns the handshake message sequence number.
   *
   * @param flight the flight to add the messages.
   * @param handshakeMessage the handshake message
   */
  fun wrapMessage(
    flight: DTLSFlight,
    handshakeMessage: HandshakeMessage,
  ) {
    handshakeMessage.messageSeq = sendMessageSequence
    sendMessageSequence++
    val epoch = dtlsContext.writeEpoch
    if (epoch == 0) {
      handshakeMessages.add(handshakeMessage)
    }
    flight.addDTLSMessage(epoch, handshakeMessage)
  }

  /**
   * Add a change cipher specs message to the flight.
   *
   * @param flight the flight to add change cipher specs wrapped messages
   * @param ccsMessage the change cipher specs message
   */
  fun wrapMessage(
    flight: DTLSFlight,
    ccsMessage: ChangeCipherSpecMessage,
  ) {
    flight.addDTLSMessage(dtlsContext.writeEpoch, ccsMessage)
  }

  /**
   * Process a received fragmented handshake message. Checks, if all fragments are available and
   * reassemble the handshake message, if so.
   *
   * @param fragment the fragmented handshake message.
   *
   *@return the reassembled generic handshake message (if all fragments are available), `null`, otherwise.
   * @throws HandshakeException if the reassembling fails
   */
  @Throws(HandshakeException::class)
  fun reassembleFragment(fragment: FragmentedHandshakeMessage): GenericHandshakeMessage? {
    log.debug("Processing {} message fragment ...", fragment.messageType)
    try {
      require(fragment.messageLength <= maxFragmentedHandshakeMessageLength) {
        "Fragmented message length exceeded (${fragment.messageLength} > $maxFragmentedHandshakeMessageLength)!"
      }
      val messageSeq = fragment.messageSeq
      if (reassembledMessage == null) {
        reassembledMessage = ReassemblingHandshakeMessage(fragment)
      } else {
        require(reassembledMessage?.messageSeq == messageSeq) {
          "Current reassemble message has different seqn ${reassembledMessage?.messageSeq} != $messageSeq"
        }
        reassembledMessage?.add(fragment)
      }
      if (reassembledMessage?.isComplete == true) {
        val message = reassembledMessage
        log.debug("Successfully re-assembled {} message", message?.messageType)
        reassembledMessage = null
        return message
      }
    } catch (ex: IllegalArgumentException) {
      throw HandshakeException(
        AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.DECRYPT_ERROR),
        ex.message,
      )
    }
    return null
  }

  /**
   * Get handshake parameter.
   *
   * @return handshake parameter.
   *
   */
  fun getParameter(): HandshakeParameter {
    val session0 = session
    return HandshakeParameter(session0.keyExchange, session0.receiveCertificateType)
  }

  fun getMaxDatagramSize(ipv6: Boolean): Int {
    val headerSize = if (ipv6) IPV6_HEADER_LENGTH else IPV4_HEADER_LENGTH
    val maximumTransmissionUnit0: Int? = maximumTransmissionUnit
    val mtu =
      maximumTransmissionUnit0
        ?: if (ipv6) {
          ipv6Mtu
        } else {
          ipv4Mtu
        }
    val size = mtu - headerSize
    check(size >= 64) { "%s, datagram size %d, mtu %d".format(if (ipv6) "IPv6" else "IPv4", size, mtu) }
    return size
  }
}
