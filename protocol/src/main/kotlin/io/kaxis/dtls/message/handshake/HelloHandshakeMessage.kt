/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.message.handshake

import io.kaxis.dtls.ProtocolVersion
import io.kaxis.dtls.Random
import io.kaxis.dtls.SessionId
import io.kaxis.dtls.extensions.*
import io.kaxis.dtls.message.HandshakeMessage
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility

/**
 * Common base for [ClientHello] and [ServerHello].
 */
abstract class HelloHandshakeMessage : HandshakeMessage {
  companion object {
    val VERSION_BITS = 8 // for major and minor each

    val RANDOM_BYTES = 32

    val SESSION_ID_LENGTH_BITS = 8
  }

  /**
   * The version of the DTLS protocol.
   */
  val protocolVersion: ProtocolVersion

  /**
   * A generated random structure.
   */
  val random: Random

  /**
   * The ID of a session the client wishes to use for this connection.
   */
  val sessionId: SessionId

  /**
   * Checks, whether this message contains a session ID.
   * @return `tue`, if the message contains a non-empty session ID
   */
  val hasSessionId: Boolean
    get() = sessionId.isNotEmpty()

  /**
   * Clients MAY request extended functionality from servers by sending data in the extensions field.
   */
  val extensions = HelloExtensions()

  /**
   * Creates a hello handshake message.
   * @param version protocol version to use
   * @param sessionId session ID to use, May be empty.
   * @throws NullPointerException if any of the parameters are `null`
   */
  constructor(version: ProtocolVersion?, sessionId: SessionId?) {
    requireNotNull(version) { "Negotiated protocol version must not be null" }
    requireNotNull(sessionId) { "ServerHello must be associated with a session ID" }
    this.protocolVersion = version
    this.sessionId = sessionId
    this.random = Random()
  }

  /**
   * Creates hello handshake message from reader.
   * @param reader reader to read parameters.
   */
  constructor(reader: DatagramReader) {
    val major = reader.read(VERSION_BITS)
    val minor = reader.read(VERSION_BITS)
    protocolVersion = ProtocolVersion.valueOf(major, minor)
    random = Random(reader.readBytes(RANDOM_BYTES))
    sessionId = SessionId(reader.readVarBytes(SESSION_ID_LENGTH_BITS))
  }

  fun writeHeader(writer: DatagramWriter) {
    writer.write(protocolVersion.major, VERSION_BITS)
    writer.write(protocolVersion.minor, VERSION_BITS)
    writer.writeBytes(random.byteArray)
    writer.writeVarBytes(sessionId, SESSION_ID_LENGTH_BITS)
  }

  override fun toString(indent: Int): String {
    val sb = StringBuilder()
    sb.append(super.toString(indent))
    val indentation = Utility.indentation(indent + 1)
    sb.append(indentation).append("Version: ").append(protocolVersion.major).append(", ").append(protocolVersion.minor)
      .append(Utility.LINE_SEPARATOR)
    sb.append(indentation).append("Random: ").append(Utility.LINE_SEPARATOR)
    sb.append(random.toString(indent + 2))
    sb.append(indentation).append("Session ID Length: ").append(sessionId.length()).append(" bytes")
      .append(Utility.LINE_SEPARATOR)
    if (sessionId.isNotEmpty()) {
      sb.append(indentation).append("Session ID: ").append(sessionId).append(Utility.LINE_SEPARATOR)
    }
    return sb.toString()
  }

  operator fun plus(extension: HelloExtension) {
    addExtension(extension)
  }

  /**
   * Add hello extension.
   * @param extension hello extension to add
   */
  fun addExtension(extension: HelloExtension) {
    extensions.addExtension(extension)
  }

  /**
   * Gets the supported point formats.
   * @return the client's supported point formats extension if available, otherwise `null`
   */
  val supportedPointFormatsExtension: SupportedPointFormatsExtension?
    get() = extensions[HelloExtension.ExtensionType.EC_POINT_FORMATS]

  /**
   * Gets the client's certificate type extension.
   * @return the client's certificate type extension if available, otherwise `null`
   */
  val clientCertificateTypeExtension: ClientCertificateTypeExtension?
    get() = extensions[HelloExtension.ExtensionType.CLIENT_CERT_TYPE]

  /**
   * Gets the servers's certificate type extension.
   * @return the servers's certificate type extension if available, otherwise `null`
   */
  val serverCertificateTypeExtension: ServerCertificateTypeExtension?
    get() = extensions[HelloExtension.ExtensionType.SERVER_CERT_TYPE]

  /**
   * Gets the _Signature and Hash Algorithms_ extension data from this message.
   * @return the extension data or `null`, if this message does not contain the _SignatureAlgorithms_ extension.
   */
  val supportedSignatureAlgorithmsExtension: SignatureAlgorithmsExtension?
    get() = extensions[HelloExtension.ExtensionType.SIGNATURE_ALGORITHMS]

  /**
   * Gets the _MaximumFragmentLength_ extension data from this message.
   * @return the extension data or `null`, if this message does not contain the _MaximumFragmentLength_ extension.
   */
  val maxFragmentLengthExtension: MaxFragmentLengthExtension?
    get() = extensions[HelloExtension.ExtensionType.MAX_FRAGMENT_LENGTH]

  /**
   * Gets the _RecordSizeLimit_ extension data from this message.
   * @return the extension data or `null`, if this message does not contain the _RecordSizeLimit_ extension.
   */
  val recordSizeLimitExtension: RecordSizeLimitExtension?
    get() = extensions[HelloExtension.ExtensionType.RECORD_SIZE_LIMIT]

  /**
   * Gets the _Server Name Indication_ extension data from this message.
   * @return the extension data or `null`, if this message does not contain the _Server Name Indication_ extension.
   */
  val serverNameExtension: ServerNameExtension?
    get() = extensions[HelloExtension.ExtensionType.SERVER_NAME]

  /**
   * Gets the _connection id_ extension data from this message.
   * @return the extension data or `null`, if this message does not contain the _connection id_ extension.
   */
  val connectionIdExtension: ConnectionIdExtension?
    get() = extensions[HelloExtension.ExtensionType.CONNECTION_ID]

  /**
   * Checks whether _ExtendedMasterSecret_ extension is present in this message.
   * @return `true`, if the _ExtendedMasterSecret_ extension is present, `false`, otherwise
   */
  val hasExtendedMasterSecretExtension: Boolean
    get() {
      return extensions.getExtension<ExtendedMasterSecretExtension>(
        HelloExtension.ExtensionType.EXTENDED_MASTER_SECRET,
      ) != null
    }

  /**
   * Checks whether _RenegotiationInfo_ extension is present in this message.
   * @return `true`, if the _RenegotiationInfo_ extension is present, `false`, otherwise
   */
  val hasRenegotiationInfoExtension: Boolean
    get() {
      return extensions.getExtension<RenegotiationInfoExtension>(
        HelloExtension.ExtensionType.RENEGOTIATION_INFO,
      ) != null
    }
}
