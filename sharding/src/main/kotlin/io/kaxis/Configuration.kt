/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis

import com.typesafe.config.Config
import com.typesafe.config.ConfigFactory
import io.kaxis.config.CertificateAuthenticationMode
import io.kaxis.dtls.CertificateType
import io.kaxis.dtls.ExtendedMasterSecretMode
import io.kaxis.dtls.ProtocolVersion
import io.kaxis.dtls.SignatureAndHashAlgorithm
import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.dtls.cipher.CipherSuiteSelector
import io.kaxis.dtls.cipher.DefaultCipherSuiteSelector
import io.kaxis.dtls.cipher.XECDHECryptography
import io.kaxis.dtls.extensions.MaxFragmentLengthExtension
import io.kaxis.dtls.message.handshake.CertificateMessage
import io.kaxis.dtls.message.handshake.CertificateRequest
import io.kaxis.dtls.message.handshake.HelloVerifyRequest
import io.kaxis.util.SslContextUtil
import java.security.cert.Certificate

interface Configuration : CborSerializable {
  companion object {
    @JvmStatic
    val config: Config = ConfigFactory.load().getConfig("kaxis.dtls")
  }

  /**
   * Get protocol version for hello verify requests to send.
   *
   * Default used fixed the protocol version DTLS 1.2 to send the HelloVerifyRequest. According
   * [RFC 6347, 4.2.1. Denial-of_service Countermeasures](https://tools.ietf.org/html/rfc6347#section-4.2.1), that
   * `HelloVerifyRequest` SHOULD be sent using protocol version DTLS 1.0. But that found to be ambiguous, because
   * it's also requested that "The server MUST use the same version number in the `HelloVerifyRequest` that it
   * would use when sending a ServerHello." With that, by default, reply the version the client sent in the
   * `HelloVerifyRequest`, and will postpone the version negotiation until the client has verified it's endpoint
   * ownership. If that client version is below DTLS 1.0, a DTLS 1.0 will be used. If a different behavior is
   * wanted, you may use the related setter to provide a fixed version for the `HelloVerifyRequest. In order to
   * provide backwards compatibility to version DTLS 1.0, configure to use protocol version DTLS 1.2.
   *
   * @return fixed protocol version, or `null`, to reply the clients version. Default is `null`.
   *
   * @see HelloVerifyRequest
   *
   */
  val protocolVersionForHelloVerifyRequests: ProtocolVersion
    get() {
      val version = config.getString("PROTOCOL_VERSION_FOR_HELLO_VERIFY_REQUESTS")
      return ProtocolVersion.valueOf(version)
    }

  /**
   * DTLS connection id length. [RFC 9146, Connection Identifier for DTLS 1.2](https://www.rfc-editor.org/rfc/rfc9146.html)
   *
   * - `""` disabled support for connection id.
   * - `0` enable support for connection id, but don't use it for incoming traffic to this peer.
   * - `n` use connection id of `n` bytes. Note: chose n large enough for the number of considered peers.
   * Recommended to have 100 times more values than peers. E.g. 65000 peers, chose not 2 bytes, chose at lease 3 bytes!
   */
  val cidLength: Int
    get() = config.getInt("CONNECTION_ID_LENGTH")

  /**
   * Use anti replay filter.
   *
   * See also [RFC 6347 4.1.2.6. Anti-Reply](https://tools.ietf.org/html/rfc6347#section-4.1.2.6).
   */
  val useAntiReplayFilter: Boolean
    get() = config.getBoolean("USE_ANTI_REPLAY_FILTER")

  /**
   * Use disabled window for anti replay filter.
   *
   * Californium uses the "sliding receive window" approach mentioned in
   * [RFC6347 4.1.2.6. Anti-Replay](https://tools.ietf.org/html/rfc6347#section-4.1.2.6).
   * That causes trouble, if some
   * records are sent on postponed routes (e.g. SMS). That would make it more
   * probable, that the record is to old for the receive window. In order not
   * to discard such records, this values defines a "disabled window", that
   * allows record to pass the filter, even if the records are too old for the
   * current receive window.
   *
   * The configured value will be subtracted from to lower receive window
   * boundary. A value of `-1` will set that calculated lower boundary
   * to `0`. Messages between lower receive window boundary and that
   * calculated value will pass the filter, for other messages the filter is
   * applied.
   *
   * @see <a href= "https://tools.ietf.org/html/rfc6347#section-4.1.2.6"
   *      target= "_blank">RFC6347 4.1.2.6. Anti-Replay</a>
   */
  val useDisabledWindowForAntiReplayFilter: Int
    get() = config.getInt("USE_DISABLED_WINDOW_FOR_ANTI_REPLAY_FILTER")

  /**
   * Update the ip-address from DTLS 1.2 CID records only for newer records based on epoch/sequence_number.
   *
   * See also [RFC 9146, Connection Identifiers for DTLS 1.2, 6. Peer Address Update](https://www.rfc-editor.org/rfc/rfc9146.html#section-6)
   */
  val updateAddressUsingCidOnNewerRecords: Boolean
    get() = config.getBoolean("UPDATE_ADDRESS_USING_CID_ON_NEWER_RECORDS")

  /**
   * Generally enable/disable the server's `HELLO_VERIFY_REQUEST`.
   *
   * **Note**: it is strongly NOT recommended to disable the `HELLO_VERIFY_REQUEST` if used with certificates!
   *
   * That creates a large amplification! See [RFC 6347, 4.2.1. Denial-of-Service Countermeasures](https://tools.ietf.org/html/rfc6347#section-4.2.1).
   *
   * DTLS use a HELLO_VERIFY_REQUEST to protect against spoofing.
   */
  val useHelloVerifyRequest: Boolean
    get() = config.getBoolean("USE_HELLO_VERIFY_REQUEST")

  /**
   * Use truncated certificate paths for client's certificate message.
   *
   * Truncate certificate path according the received certificate authorities in the [CertificateRequest] for
   * the client's [CertificateMessage].
   */
  val truncateClientCertificatePath: Boolean
    get() = config.getBoolean("TRUNCATE_CLIENT_CERTIFICATE_PATH")

  /**
   * Use truncated certificate paths for validation.
   *
   * Truncate certificate path according to the available trusted certificates before validation.
   */
  val truncateCertificatePathForValidation: Boolean
    get() = config.getBoolean("TRUNCATE_CERTIFICATE_PATH_FOR_VALIDATION")

  /**
   * Use recommended [CipherSuite]s only.
   *
   * DTLS recommended cipher-suites only.
   */
  val recommendedCipherSuitesOnly: Boolean
    get() = config.getBoolean("RECOMMENDED_CIPHER_SUITES_ONLY")

  /**
   * Use recommended [XECDHECryptography.SupportedGroup]s only.
   *
   * DTLS recommended ECC curves/groups only.
   */
  val recommendedCurvesOnly: Boolean
    get() = config.getBoolean("RECOMMENDED_CURVES_ONLY")

  /**
   * Use recommended [SignatureAndHashAlgorithm]s only.
   *
   * DTLS recommended signature- and hash-algorithms only.
   */
  val recommendedSignatureAndHashAlgorithmsOnly: Boolean
    get() = config.getBoolean("RECOMMENDED_SIGNATURE_AND_HASH_ALGORITHMS_ONLY")

  /**
   * Preselected [CipherSuite]s.
   *
   * If not recommended cipher suites are intended to be used, switch off `DTLS_RECOMMENDED_CIPHER_SUITES_ONLY`.
   *
   * The supported cipher suites are evaluated at runtime and may differ from the ones when creating this properties file.
   */
  val preselectedCipherSuites: MutableList<CipherSuite>
    get() {
      return try {
        CipherSuite.getTypesByNames(config.getStringList("PRESELECTED_CIPHER_SUITES"))
      } catch (e: Throwable) {
        CipherSuite.getCipherSuites(false, supportedCipherSuitesOnly = false)
      }
    }

  /**
   * Select [CipherSuite]s.
   *
   * If not recommended cipher suites are intended to be used, witch off `DTLS_RECOMMENDED_CIPHER_SUITES_ONLY`.
   *
   * The supported cipher suites are evaluated at runtime and may differ from the ones when creating this properties file.
   */
  val cipherSuites: List<CipherSuite>
    get() {
      return try {
        CipherSuite.getTypesByNames(config.getStringList("CIPHER_SUITES")).ifEmpty {
          CipherSuite.getCipherSuites(false, supportedCipherSuitesOnly = true)
        }
      } catch (e: Throwable) {
        CipherSuite.getCipherSuites(recommendedCipherSuitesOnly = false, supportedCipherSuitesOnly = true)
      }
    }

  /**
   * Select curves [XECDHECryptography.SupportedGroup]s.
   *
   * Defaults to all supported curves of the JCE at runtimes.
   */
  val curves: List<XECDHECryptography.SupportedGroup>
    get() {
      return try {
        XECDHECryptography.SupportedGroup.getTypesByNames(config.getStringList("CURVES")).ifEmpty {
          XECDHECryptography.SupportedGroup.getUsableGroups()
        }
      } catch (e: Throwable) {
        XECDHECryptography.SupportedGroup.getUsableGroups()
      }
    }

  /**
   * Select [SignatureAndHashAlgorithm]s.
   *
   * List of DTLS signature- and hash-algorithms. E.g SHA256withECDSA or ED25519.
   */
  val signatureAndHashAlgorithms: MutableList<SignatureAndHashAlgorithm>
    get() {
      return try {
        config
          .getStringList(
            "SIGNATURE_AND_HASH_ALGORITHMS",
          ).map(SignatureAndHashAlgorithm::valueOf)
          .toMutableList()
          .ifEmpty {
            mutableListOf(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
          }
      } catch (e: Throwable) {
        mutableListOf(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
      }
    }

  /**
   * Select [CipherSuite.CertificateKeyAlgorithm]s.
   *
   * On the client side used to select the default cipher-suites, on the server side to negotiate the client's certificate.
   */
  val certificateKeyAlgorithms: MutableList<CipherSuite.CertificateKeyAlgorithm>
    get() {
      val default = arrayListOf(CipherSuite.CertificateKeyAlgorithm.EC, CipherSuite.CertificateKeyAlgorithm.RSA)
      return try {
        CipherSuite.CertificateKeyAlgorithm
          .getTypesByNames(
            config.getStringList("CERTIFICATE_KEY_ALGORITHMS"),
          ).ifEmpty { default }
      } catch (e: Throwable) {
        default
      }
    }

  /**
   * Specify the usage and support of "server name indication".
   *
   * The support on the server side currently includes a server name specific PSK secret lookup and
   * to forward the server name to the `CoAP` stack.
   */
  val useServerNameIndication: Boolean
    get() = config.getBoolean("USE_SERVER_NAME_INDICATION")

  /**
   * Defines the usage of the "extend master secret" extension. See [RFC 7627](https://tools.ietf.org/html/rfc7627) for details.
   */
  val extendedMasterSecretMode: ExtendedMasterSecretMode
    get() {
      return try {
        config.getEnum(ExtendedMasterSecretMode::class.java, "EXTENDED_MASTER_SECRET_MODE")
      } catch (e: Throwable) {
        ExtendedMasterSecretMode.ENABLED
      }
    }

  /**
   * Specify the maximum number of DTLS retransmissions.
   *
   * DTLS maximum number of flight retransmissions.
   */
  val maxRetransmissions: Int
    get() = config.getInt("MAX_RETRANSMISSIONS")

  val maximumTransmissionUnit: Int?
    get() {
      return try {
        config.getInt("DTLS_MAX_TRANSMISSION_UNIT")
      } catch (e: Throwable) {
        null
      }
    }

  /**
   * Specify the number of DTLS retransmissions before the attempt to transmit a flight in back-off mode.
   *
   * [RFC 6347, Section 4.1.1.1, Page 12](https://tools.ietf.org/html/rfc6347#page-12)
   *
   * In back-off mode, UDP datagrams of maximum 512 bytes or the negotiated
   * records size, if that is smaller, are used. Each handshake message is
   * placed in one DTLS record, or more DTLS records, if the handshake message
   * is too large and must be fragmented. Besides, of the CCS and FINISH DTLS
   * records, which send together in one UDP datagram, all other records are sent in separate datagrams.
   *
   * The [useMultiHandshakeMessageRecords] and [useMultiRecordMessages] has precedence over the back-off
   * definition. value `0`, to disable it, `null`, for default [maxRetransmissions] / 2.
   */
  val retransmissionBackoff: Int
    get() =
      try {
        config.getInt("RETRANSMISSION_BACKOFF")
      } catch (e: Throwable) {
        0
      }

  /**
   * Enable or disable the server to use a session ID in order to support or disable session resumption.
   */
  val serverUseSessionId: Boolean
    get() =
      try {
        config.getBoolean("SERVER_USE_SESSION_ID")
      } catch (e: Throwable) {
        true
      }

  /**
   * Enable early stop of retransmissions.
   *
   * Stop retransmission on receiving the first message of the next flight, not waiting for the last message.
   */
  val useEarlyStopRetransmission: Boolean
    get() =
      try {
        config.getBoolean("USE_EARLY_STOP_RETRANSMISSION")
      } catch (e: Throwable) {
        true
      }

  /**
   * Specify the record size limit. Between 64 and 16k.
   *
   * See [RFC 8449](https://tools.ietf.org/html/rfc8449) for details.
   */
  val recordSizeLimit: Int
    get() =
      try {
        config.getInt("RECORD_SIZE_LIMIT")
      } catch (e: Throwable) {
        0
      }

  /**
   * Specify the maximum fragment length.
   *
   * See [RFC 6066, Section 4](https://tools.ietf.org/html/rfc6066#section-4).
   */
  val maxFragmentLength: MaxFragmentLengthExtension.Length
    get() =
      try {
        MaxFragmentLengthExtension.Length.fromValue(config.getInt("MAX_FRAGMENT_SIZE"))
          ?: MaxFragmentLengthExtension.Length.BYTES_2048
      } catch (e: Throwable) {
        MaxFragmentLengthExtension.Length.BYTES_2048
      }

  /**
   * Specify the maximum length of reassembled fragmented handshake messages.
   *
   * Must be large enough for used certificates.
   */
  val maxFragmentedHandshakeMessageLength: Int
    get() =
      try {
        config.getInt("MAX_FRAGMENTED_HANDSHAKE_MESSAGE_LENGTH")
      } catch (e: Throwable) {
        8192
      }

  /**
   * Enable to use multiple DTLS records in UDP messages.
   */
  val useMultiRecordMessages: Boolean?
    get() =
      try {
        config.getBoolean("USE_MULTI_RECORD_MESSAGES")
      } catch (e: Throwable) {
        null
      }

  /**
   * Enable to use multiple DTLS records in UDP messages.
   *
   * Not all libraries may have implemented this!
   */
  val useMultiHandshakeMessageRecords: Boolean?
    get() =
      try {
        config.getBoolean("USE_MULTI_HANDSHAKE_MESSAGE_RECORDS")
      } catch (e: Throwable) {
        null
      }

  /**
   * Specify the client's certificate authentication mode.
   *
   * Used on the server-side to request a client certificate for authentication.
   */
  val clientAuthenticationMode: CertificateAuthenticationMode
    get() {
      return try {
        CertificateAuthenticationMode.valueOf(config.getString("CLIENT_AUTHENTICATION_MODE"))
      } catch (e: Throwable) {
        CertificateAuthenticationMode.NEEDED
      }
    }

  /**
   * Enable the DTLS client to verify the server certificate's subjects.
   */
  val verifyServerCertificatesSubject: Boolean
    get() = config.getBoolean("VERIFY_SERVER_CERTIFICATES_SUBJECT")

  /**
   * Specify the support certificate types.
   */
  val certificateTypes: List<CertificateType>
    get() {
      return try {
        config.getStringList("CERTIFICATE_TYPES").map(CertificateType::valueOf).ifEmpty {
          arrayListOf(CertificateType.RAW_PUBLIC_KEY, CertificateType.X_509)
        }
      } catch (e: Throwable) {
        arrayListOf(CertificateType.RAW_PUBLIC_KEY, CertificateType.X_509)
      }
    }

  /**
   * Specify the MTU (Maximum Transmission Unit).
   *
   * **Note**: DTLS MTU (Maximum Transmission Unit) must be used, if the MTU of the local network doesn't apply, E.g
   * if ip-tunnels are used, this value must be provided in order to consider a smaller PMTU.
   */
  val maxTransmissionUnit: Int
    get() =
      try {
        config.getInt("MAX_TRANSMISSION_UNIT")
      } catch (e: Throwable) {
        64
      }

  /**
   * Specify an MTU (Maximum Transmission Unit) limit for (link local) auto-detection.
   *
   * Limits the maximum number of bytes sent in one transmission.
   *
   * **Note**: a previous version took the local link MTU without limits. That results in possibly
   * larger MTU, E.g for localhost or some cloud nodes using "jumbo frames". If a larger MTU
   * is required to be detectable, please adjust this limit to the required value.
   */
  val maxTransmissionUnitLimit: Int
    get() {
      return try {
        config.getInt("MAX_TRANSMISSION_UNIT_LIMIT")
      } catch (e: Throwable) {
        1500
      }
    }

  /**
   * Specify the secure renegotiation mode.
   *
   * @see <a href="https://tools.ietf.org/html/rfc5746" target="_blank" >RFC 5746</a>
   */
  val secureRenegotiation: SecureRenegotiation
    get() {
      return try {
        SecureRenegotiation.valueOf(config.getString("SECURE_RENEGOTIATION_MODE"))
      } catch (e: Throwable) {
        SecureRenegotiation.WANTED
      }
    }

  /**
   * Support key material export.
   *
   * @see <a href="https://tools.ietf.org/html/rfc5705" target="_blank">RFC 5705</a>
   */
  val supportKeyMaterialExport: Boolean
    get() {
      return config.getBoolean("SUPPORT_KEY_MATERIAL_EXPORT")
    }

  /**
   * DTLS secure renegotiation.
   *
   * @see <a href="https://tools.ietf.org/html/rfc5746" target="_blank" >RFC 5746</a>
   */
  enum class SecureRenegotiation {
    NONE,
    WANTED,
    NEEDED,
  }

  val keyStorePassword: String
    get() {
      return config.getString("KEY_STORE_PASSWORD")
    }

  val keyStoreLocation: String
    get() {
      return config.getString("KEY_STORE_LOCATION")
    }

  val trustStorePassword: String
    get() {
      return config.getString("TRUST_STORE_PASSWORD")
    }

  val trustStoreLocation: String
    get() {
      return config.getString("TRUST_STORE_LOCATION")
    }

  // bellow properties are used for server handshake.

  val cipherSuiteSelector: CipherSuiteSelector
    get() = DefaultCipherSuiteSelector()

  val supportedCertificateKeyAlgorithms: MutableList<CipherSuite.CertificateKeyAlgorithm>
    get() = certificateKeyAlgorithms

  val supportedCipherSuites: MutableList<CipherSuite>
    get() {

      var ciphers: MutableList<CipherSuite> = arrayListOf()
      ciphers.addAll(
        CipherSuite.getCertificateCipherSuites(recommendedCipherSuitesOnly, supportedCertificateKeyAlgorithms),
      )
      // PSK
      ciphers.addAll(
        CipherSuite.getCipherSuitesByKeyExchangeAlgorithm(
          recommendedCipherSuitesOnly,
          CipherSuite.KeyExchangeAlgorithm.ECDHE_PSK,
        ),
      )
      ciphers.addAll(
        CipherSuite.getCipherSuitesByKeyExchangeAlgorithm(
          recommendedCipherSuitesOnly,
          CipherSuite.KeyExchangeAlgorithm.PSK,
        ),
      )
      if (preselectedCipherSuites.isNotEmpty()) {
        ciphers = CipherSuite.preselectCipherSuites(ciphers, preselectedCipherSuites)
      }

      return ciphers
    }

  val supportedGroups: List<XECDHECryptography.SupportedGroup>
    get() {
      val defaultGroups: MutableList<XECDHECryptography.SupportedGroup> =
        XECDHECryptography.SupportedGroup.getPreferredGroups().toMutableList()
      if (curves.isNotEmpty()) {
        defaultGroups.addAll(curves)
      }
      return defaultGroups
    }

  val useSessionId: Boolean
    get() = serverUseSessionId

  val supportedClientCertificateTypes: MutableList<CertificateType>
    get() {
      val defaultClientCertificateTypes: MutableList<CertificateType> = arrayListOf()
      defaultClientCertificateTypes.add(CertificateType.X_509)
      defaultClientCertificateTypes.add(CertificateType.RAW_PUBLIC_KEY)
      return defaultClientCertificateTypes
    }

  val supportedServerCertificateTypes: MutableList<CertificateType>
    get() {
      val defaultClientCertificateTypes: MutableList<CertificateType> = arrayListOf()
      defaultClientCertificateTypes.add(CertificateType.X_509)
      defaultClientCertificateTypes.add(CertificateType.RAW_PUBLIC_KEY)
      return defaultClientCertificateTypes
    }

  val supportedSignatureAndHashAlgorithms: MutableList<SignatureAndHashAlgorithm>
    get() = signatureAndHashAlgorithms

  val sniEnabled: Boolean
    get() = useServerNameIndication

  val serverCredentials: SslContextUtil.Credentials?
    get() {
      return try {
        SslContextUtil.loadCredentials(
          SslContextUtil.CLASSPATH_SCHEME + keyStoreLocation,
          "server",
          keyStorePassword.toCharArray(),
          keyStorePassword.toCharArray(),
        )
      } catch (ex: NullPointerException) {
        null
      }
    }

  val trustedCertificates: Array<Certificate>?
    get() {
      return SslContextUtil.loadTrustedCertificates(
        SslContextUtil.CLASSPATH_SCHEME + trustStoreLocation,
        "root",
        trustStorePassword.toCharArray(),
      )
    }
}
