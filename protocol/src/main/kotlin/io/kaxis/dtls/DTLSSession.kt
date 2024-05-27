/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls

import io.kaxis.Bytes
import io.kaxis.auth.PrincipalSerializer
import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.dtls.cipher.PseudoRandomFunction
import io.kaxis.dtls.cipher.XECDHECryptography
import io.kaxis.dtls.extensions.RecordSizeLimitExtension
import io.kaxis.util.*
import java.security.GeneralSecurityException
import java.security.Principal
import java.util.*
import javax.crypto.SecretKey
import javax.security.auth.Destroyable

/**
 * Represents a DTLS session between two peers. Keeps track of the negotiated parameter.
 */
class DTLSSession : Destroyable {
  companion object {
    // 2^14 bytes as defined by DTLS 1.2 spec, Section 4.1
    private const val MAX_FRAGMENT_LENGTH_DEFAULT = 16384

    /**
     * Version number for serialization.
     */
    private const val VERSION = 3

    /**
     * Version number for serialization before introducing [secureRenegotiation].
     */
    private const val VERSION_DEPRECATED = 2

    /**
     * Supported version for [fromReader]
     */
    private val VERSIONS = SerializationUtil.SupportedVersionsMatcher(VERSION, VERSION_DEPRECATED)

    fun fromReader(reader: DatagramReader): DTLSSession? {
      val matcher = VERSIONS.matcher()
      val length = SerializationUtil.readStartItem(reader, matcher, Short.SIZE_BITS)
      return if (0 < length) {
        val rangeReader = reader.createRangeReader(length)
        DTLSSession(matcher.readVersion, rangeReader)
      } else {
        null
      }
    }
  }

  /**
   * An arbitrary byte sequence chosen by the server to identify this session.
   */
  var sessionIdentifier: SessionId = SessionId.emptySessionId()
    /**
     * Sets the session identifier. Resets the [masterSecret], if the session identifier is changed.
     * @param sessionIdentifier new session identifier
     * @throws NullPointerException if the provided session identifier is `null`
     * @throws IllegalArgumentException if the provided session identifier is neither empty nor different to the available one.
     */
    set(sessionIdentifier) {
      requireNotNull(sessionIdentifier) { "session identifier must not be null!" }
      if (sessionIdentifier != field || sessionIdentifier.isEmpty()) {
        // reset master secret
        SecretUtil.destroy(this.masterSecret)
        field = sessionIdentifier
      } else {
        throw IllegalArgumentException("no new session identifier?")
      }
    }

  /**
   * Protocol version. Only [ProtocolVersion.VERSION_DTLS_1_2] is supported.
   */
  var protocolVersion = ProtocolVersion.VERSION_DTLS_1_2
    /**
     * Sets protocol version. Only [ProtocolVersion.VERSION_DTLS_1_2] is supported.
     * @param protocolVersion protocol version
     * @throws IllegalArgumentException if other version as [ProtocolVersion.VERSION_DTLS_1_2] is provided.
     */
    set(protocolVersion) {
      require(ProtocolVersion.VERSION_DTLS_1_2 == protocolVersion) { "$protocolVersion is not supported" }
      field = ProtocolVersion.VERSION_DTLS_1_2
    }

  /**
   * Peer identity. which is the presentation of any entity.
   */
  var peerIdentity: Principal? = null

  private var recordSizeLimit0: Int = 0

  /**
   * Record size limit.
   */
  var recordSizeLimit: Int
    get() = recordSizeLimit0

    /**
     * Sets the negotiated record size limit for this session.
     * @param limit record size limit
     * @throws IllegalArgumentException if the record size limit is not in range
     */
    set(limit) {
      recordSizeLimit0 = RecordSizeLimitExtension.ensureInRange(limit)
    }

  /**
   * Maximum used fragment length.
   */
  var maxFragmentLength = MAX_FRAGMENT_LENGTH_DEFAULT
    /**
     * Sets the maximum amount of unencrypted payload data that can be received and processed by this session's peer
     * in a single DTLS record.
     *
     * The value of this property corresponds directly to the _DTLSPlaintext.length_ field as defined in [DTLS 1.2 spec, Section 4.3.1](https://tools.ietf.org/html/rfc6347#section-4.3.1).
     *
     * The default value of this property is 2^14 bytes.
     *
     * This method checks if a fragment of the given maximum length can be transmitted in a single datagram without
     * the need for IP fragmentation. If not the given length is reduced to the maximum value for which this is possible.
     * @param length the maximum length in bytes
     * @throws IllegalArgumentException if the given length is < 0 or > 2^14
     */
    set(length) {
      require(length in 0..MAX_FRAGMENT_LENGTH_DEFAULT) {
        "Max. fragment length must be in range [0...$MAX_FRAGMENT_LENGTH_DEFAULT]"
      }
      field = length
    }

  val effectiveFragmentLimit: Int
    /**
     * Gets effective fragment limit. Either [recordSizeLimit], if received, or [maxFragmentLength].
     * @return effective fragment limit.
     */
    get() {
      return if (this.recordSizeLimit0 != 0) {
        this.recordSizeLimit0
      } else {
        this.maxFragmentLength
      }
    }

  private var cipherSuite0: CipherSuite = CipherSuite.TLS_NULL_WITH_NULL_NULL

  /**
   * Specifies the pseudo-random function (PRF) used to generate keying material, the bulk data encryption algorithm
   * (such as `null`, AES, etc.) and the MAC algorithm (such as HMAC-SHA1). It also defines
   * cryptographic attributes such as the mac_length. (See TLS 1.2, Appendix A.6 for formal definition.)
   */
  var cipherSuite: CipherSuite
    get() = cipherSuite0
    set(cipherSuite) {
      require(cipherSuite.isValidForNegotiation) { "Negotiated cipher suite must be valid for negotiation!" }
      cipherSuite0 = cipherSuite
    }

  val maxCiphertextExpansion: Int
    get() {
      checkNotNull(cipherSuite) { "Missing cipher suite." }
      return cipherSuite.maxCipherTextExpansion
    }

  val keyExchange: CipherSuite.KeyExchangeAlgorithm
    get() = cipherSuite.keyExchange

  /**
   * Specifies the negotiated signature and hash algorithm to be used to sign the server key exchange message.
   */
  var signatureAndHashAlgorithm: SignatureAndHashAlgorithm? = null

  /**
   * Specifies the negotiated ec-group to be used for the ECDHE key exchange message.
   */
  var ecGroup: XECDHECryptography.SupportedGroup = XECDHECryptography.SupportedGroup.secp256r1

  var compressionMethod = CompressionMethod.NULL

  /**
   * Use extended master secret.
   *
   * See [RFC 7627](https://tools.ietf.org/html/rfc7627).
   */
  var extendedMasterSecret: Boolean = false

  /**
   * Use for secure renegotiation.
   *
   * See [RFC 5746](https://tools.ietf.org/html/rfc5746) for additional details.
   */
  var secureRenegotiation: Boolean = false

  /**
   * The Shadow of [DTLSSession]'s [masterSecret].
   */
  private var masterSecret0: SecretKey? = null

  /**
   * The 48-byte master secret shared by client and server to derive key material from. Only set for resumable sessions!
   */
  var masterSecret: SecretKey? = null
    get() = SecretUtil.create(masterSecret0)

    /**
     * Sets the master secret to be use on session resumptions. Once the master secret has been set,
     * it cannot be changed without changing the session id ahead. If the session id is empty, the session doesn't
     * support resumption and therefore the master secret is not set.
     * @param masterSecret the secret, copied on set
     * @throws NullPointerException if the master secret is `null`
     * @throws IllegalArgumentException if the secret is not exactly 48 bytes (see [RFC 5246(TLS 1.2), section 8.1](https://tools.ietf.org/html/rfc5246#section-8.1))
     * @throws IllegalStateException if the master secret is already set
     */
    set(masterSecret) {
      // don't overwrite the master secret, once it has been set in this session
      check(masterSecret0 == null) { "master secret already available!" }
      if (sessionIdentifier.isNotEmpty()) {
        requireNotNull(masterSecret) { "Master secret must not be null" }
        // get length
        val secret = masterSecret.encoded
        // clear secret immediately, only length is required
        Bytes.clear(secret)
        require(secret.size == PseudoRandomFunction.Label.MASTER_SECRET_LABEL.length) {
          "Master secret must consist of exactly %d bytes but has %d bytes".format(
            PseudoRandomFunction.Label.MASTER_SECRET_LABEL.length,
            secret.size,
          )
        }
        field = SecretUtil.create(masterSecret)
      }
      this.creationTime = System.currentTimeMillis()
    }

  /**
   * Indicates the type of certificate to send to the peer in a CERTIFICATE message.
   */
  var sendCertificateType: CertificateType = CertificateType.X_509

  /**
   * Indicates the type of certificate to expect from the peer in a CERTIFICATE message.
   */
  var receiveCertificateType: CertificateType = CertificateType.X_509

  var creationTime: Long = System.currentTimeMillis()

  // AVOID StackOverflowError
  private var hostName0: String? = null
  var hostName: String?
    get() = hostName0

    /**
     * Set the (virtual) host name for the server that this session has been established for.
     *
     * Sets the [serverNames] accordingly.
     * @param hostname the virtual host name at the peer (maybe `null`).
     */
    set(hostname) {
      hostName0 = hostname
      this.serverNames0 = null
      if (hostname != null) {
        this.serverNames0 =
          ServerNames.newInstance(
            ServerName.from(
              ServerName.NameType.HOST_NAME,
              hostname.toByteArray(ServerName.CHARSET),
            ),
          )
      }
    }

  // AVOID StackOverflowError
  private var serverNames0: ServerNames? = null
  var serverNames: ServerNames?
    get() = serverNames0

    /**
     * Sets the server names for the server that this session has been established for.
     *
     * Sets the [hostName] accordingly.
     * @param serverNames the server names (maybe `null`).
     */
    set(serverNames) {
      serverNames0 = serverNames
      this.hostName0 = null
      if (serverNames != null) {
        val serverName = serverNames.getServerName(ServerName.NameType.HOST_NAME)
        if (serverName != null) {
          hostName0 = serverName.nameAsString
        }
      }
    }

  var peerSupportsSni: Boolean = false

  /**
   * Creates a session using default values for all fields.
   */
  constructor() {
    creationTime = System.currentTimeMillis()
  }

  /**
   * Creates a session using default values for all fields, except the [hostName] and [serverNames].
   * @param hostname hostname, or `null`, if not used.
   */
  constructor(hostname: String) {
    creationTime = System.currentTimeMillis()
    hostName = hostname
  }

  /**
   * Creates a new session based on a given set of crypto parameter of another session that is to be resumed.
   * @param session session to resume
   */
  constructor(session: DTLSSession) {
    set(session)
  }

  /**
   * Create instance from reader.
   *
   * ```
   *  The DTLSSession will be transform in AKKA Cluster nodes as serialization objects.
   * ```
   *
   * @param version version of serialized data.
   * @param reader reader with dtls session state.
   * @throws IllegalArgumentException if the version differs or the data is erroneous
   */
  private constructor(version: Int, reader: DatagramReader) {
    creationTime = reader.readLong(Long.SIZE_BITS)
    if (reader.readNextByte() == 1.toByte()) {
      serverNames0 = ServerNames.newInstance()
      try {
        serverNames0!!.decode(reader)
        val serverName = serverNames0!!.getServerName(ServerName.NameType.HOST_NAME)
        if (serverName != null) {
          hostName0 = serverName.nameAsString
        }
      } catch (e: IllegalArgumentException) {
        serverNames0 = null
      }
    }
    var size = reader.read(Short.SIZE_BITS)
    if (size < 0xffff) {
      recordSizeLimit0 = size
    }
    size = reader.read(Short.SIZE_BITS)
    maxFragmentLength = size
    val data = reader.readVarBytes(Byte.SIZE_BITS)
    if (data != null) {
      sessionIdentifier = SessionId(data)
    }
    var code = reader.read(Short.SIZE_BITS)
    cipherSuite = CipherSuite.getTypeByCode(code) ?: throw IllegalArgumentException(
      "unknown cipher suite 0x${
        Integer.toHexString(code)
      }!",
    )
    code = reader.read(Byte.SIZE_BITS)
    compressionMethod = CompressionMethod.getMethodByCode(code)
      ?: throw IllegalArgumentException("unknown compression method 0x${Integer.toHexString(code)}!")
    code = reader.read(Byte.SIZE_BITS)
    sendCertificateType = CertificateType.getTypeFromCode(code)
      ?: throw IllegalArgumentException("unknown send certificate type 0x${Integer.toHexString(code)}!")
    code = reader.read(Byte.SIZE_BITS)
    receiveCertificateType = CertificateType.getTypeFromCode(code)
      ?: throw IllegalArgumentException("unknown send certificate type 9x${Integer.toHexString(code)}!")
    if (version > VERSION_DEPRECATED) {
      secureRenegotiation = (reader.read(Byte.SIZE_BITS) == 1)
    }
    extendedMasterSecret = (reader.read(Byte.SIZE_BITS) == 1)
    masterSecret0 = SecretSerializationUtil.readSecretKey(reader)
    if (reader.readNextByte() == 1.toByte()) {
      val hashId = reader.read(Byte.SIZE_BITS)
      val signatureId = reader.read(Byte.SIZE_BITS)
      signatureAndHashAlgorithm = SignatureAndHashAlgorithm(hashId, signatureId)
    }
    if (reader.readNextByte() == 1.toByte()) {
      val groupId = reader.read(Short.SIZE_BITS)
      ecGroup = XECDHECryptography.SupportedGroup.fromId(groupId)
        ?: throw IllegalArgumentException("unknown ec-group 0x${Integer.toHexString(groupId)}!")
    }
    if (reader.readNextByte() == 1.toByte()) {
      try {
        peerIdentity = PrincipalSerializer.deserialize(reader)
      } catch (e: GeneralSecurityException) {
        throw IllegalArgumentException("principal failure", e)
      }
    }
    reader.assertFinished("dtls-session")
  }

  /**
   * Sets session. Sets all fields of this session from the values of the provided sesion.
   * @param session session to set
   */
  fun set(session: DTLSSession) {
    creationTime = session.creationTime
    sessionIdentifier = session.sessionIdentifier
    protocolVersion = session.protocolVersion
    masterSecret0 = session.masterSecret0
    peerIdentity = session.peerIdentity
    cipherSuite = session.cipherSuite
    compressionMethod = session.compressionMethod
    signatureAndHashAlgorithm = session.signatureAndHashAlgorithm
    ecGroup = session.ecGroup
    extendedMasterSecret = session.extendedMasterSecret
    secureRenegotiation = session.secureRenegotiation
    sendCertificateType = session.sendCertificateType
    receiveCertificateType = session.receiveCertificateType
    recordSizeLimit0 = session.recordSizeLimit0
    maxFragmentLength = session.maxFragmentLength
    serverNames0 = session.serverNames0
  }

  override fun destroy() {
    SecretUtil.destroy(masterSecret0)
    masterSecret0 = null
    extendedMasterSecret = false
    secureRenegotiation = false
    cipherSuite0 = CipherSuite.TLS_NULL_WITH_NULL_NULL
    compressionMethod = CompressionMethod.NULL
    signatureAndHashAlgorithm = null
    ecGroup = XECDHECryptography.SupportedGroup.secp256r1
    peerIdentity = null
    sendCertificateType = CertificateType.X_509
    receiveCertificateType = CertificateType.X_509
  }

  override fun isDestroyed(): Boolean {
    return SecretUtil.isDestroyed(masterSecret0)
  }

  /**
   * Calculate the pseudo random function for exporter as defined in [RFC 5246](https://tools.ietf.org/html/rfc5246#section-5)
   * and [RFC 5705](https://tools.ietf.org/html/rfc5705#section-4) using the
   * negotiated [cipherSuite] and [masterSecret].
   * @param label label to use
   * @param seed seed to use
   * @param length length of the key
   * @return calculated pseudo random for exporter
   * @throws IllegalArgumentException if label is not allowed for exporter
   */
  fun exportKeyMaterial(
    label: ByteArray,
    seed: ByteArray,
    length: Int,
  ): ByteArray {
    val hmac = cipherSuite.threadLocalPseudoRandomFunctionMac ?: throw GeneralSecurityException("Local MAC not found!")
    val ms = masterSecret0 ?: throw IllegalStateException("MasterSecret have not been set.")
    return PseudoRandomFunction.doExporterPRF(hmac, ms, label, seed, length)
  }

  override fun hashCode(): Int {
    return if (this.sessionIdentifier.isEmpty()) creationTime.toInt() else sessionIdentifier.hashCode()
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) {
      return true
    } else if (other == null) {
      return false
    } else if (other !is DTLSSession) {
      return false
    } else {
      if (!SecretUtil.equals(masterSecret, other.masterSecret)) {
        return false
      }
      if (!Bytes.equals(sessionIdentifier, other.sessionIdentifier)) {
        return false
      }
      if (cipherSuite != other.cipherSuite) {
        return false
      }
      if (compressionMethod != other.compressionMethod) {
        return false
      }
      if (extendedMasterSecret != other.extendedMasterSecret) {
        return false
      }
      if (secureRenegotiation != other.secureRenegotiation) {
        return false
      }
      if (peerSupportsSni != other.peerSupportsSni) {
        return false
      }
      if (sendCertificateType != other.sendCertificateType) {
        return false
      }
      if (receiveCertificateType != other.receiveCertificateType) {
        return false
      }
      if (ecGroup != other.ecGroup) {
        return false
      }
      if (creationTime != other.creationTime) {
        return false
      }
      if (!Objects.equals(signatureAndHashAlgorithm, other.signatureAndHashAlgorithm)) {
        return false
      }
      if (!Objects.equals(serverNames, other.serverNames)) {
        return false
      }
      if (!Objects.equals(recordSizeLimit0, other.recordSizeLimit0)) {
        return false
      }
      if (!Objects.equals(peerIdentity, other.peerIdentity)) {
        return false
      }
      if (!Objects.equals(protocolVersion, other.protocolVersion)) {
        return false
      }
      return true
    }
  }

  /**
   * Write dtls session state.
   *
   * Note: the stream will contain not encrypted critial credentials. It is required to protect this data before exporting it.
   * @param writer writer for dtls session state.
   */
  fun writeTo(writer: DatagramWriter) {
    val position = SerializationUtil.writeStartItem(writer, VERSION, Short.SIZE_BITS)
    writer.writeLong(creationTime, Long.SIZE_BITS)
    if (serverNames == null) {
      writer.write(0, Byte.SIZE_BITS)
    } else {
      writer.write(1, Byte.SIZE_BITS)
      serverNames!!.encode(writer)
    }
    if (recordSizeLimit0
      in RecordSizeLimitExtension.MIN_RECORD_SIZE_LIMIT..RecordSizeLimitExtension.MAX_RECORD_SIZE_LIMIT
    ) {
      writer.write(recordSizeLimit0, Short.SIZE_BITS)
    } else {
      writer.write(0xffff, Short.SIZE_BITS)
    }
    writer.write(maxFragmentLength, Short.SIZE_BITS)
    writer.writeVarBytes(sessionIdentifier, Byte.SIZE_BITS)
    writer.write(cipherSuite.code, Short.SIZE_BITS)
    writer.write(compressionMethod.code, Byte.SIZE_BITS)
    writer.write(sendCertificateType.code, Byte.SIZE_BITS)
    writer.write(receiveCertificateType.code, Byte.SIZE_BITS)
    writer.write(if (secureRenegotiation) 1 else 0, Byte.SIZE_BITS)
    writer.write(if (extendedMasterSecret) 1 else 0, Byte.SIZE_BITS)
    SecretSerializationUtil.write(writer, masterSecret)
    if (signatureAndHashAlgorithm == null) {
      writer.write(0, Byte.SIZE_BITS)
    } else {
      writer.write(1, Byte.SIZE_BITS)
      writer.write(signatureAndHashAlgorithm!!.hashAlgorithmCode, Byte.SIZE_BITS)
      writer.write(signatureAndHashAlgorithm!!.signatureAlgorithmCode, Byte.SIZE_BITS)
    }
    if (ecGroup == null) {
      writer.write(0, Byte.SIZE_BITS)
    } else {
      writer.write(1, Byte.SIZE_BITS)
      writer.write(ecGroup.id, Short.SIZE_BITS)
    }
    if (peerIdentity == null) {
      writer.write(0, Byte.SIZE_BITS)
    } else {
      writer.write(1, Byte.SIZE_BITS)
      PrincipalSerializer.serialize(peerIdentity, writer)
    }
    SerializationUtil.writeFinishedItem(writer, position, Short.SIZE_BITS)
  }
}
