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

import io.kaxis.dtls.CompressionMethod
import io.kaxis.dtls.HandshakeType
import io.kaxis.dtls.ProtocolVersion
import io.kaxis.dtls.SessionId
import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.dtls.message.AlertMessage
import io.kaxis.exception.HandshakeException
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility

/**
 * A TLS handshake message sent by a server in response to a [ClientHello] message received from a client. The
 * server will send this message in response to a [ClientHello] message when it was able to find an acceptable set
 * of algorithms. If it cannot find such a match, it will respond with a handshake failure alert. See
 * [RFC 5246](https://tools.ietf.org/html/rfc5246#section-7.4.1.3) for further details.
 */
class ServerHello : HelloHandshakeMessage {
  companion object {
    /**
     * Creates a _Server Hello_ object from its binary encoding as used on the wire.
     * @param reader reader for the binary encoding of the message.
     * @return the object representation
     * @throws HandshakeException if the cipher suite code selected by the server is either unknown, i.e. not
     * defined in [CipherSuite] at all, or not [CipherSuite.isValidForNegotiation].
     */
    fun fromReader(reader: DatagramReader): ServerHello = ServerHello(reader)
  }

  /**
   * The single [CipherSuite] selected by the server from the list in [ClientHello].cipher_suites.
   */
  val cipherSuite: CipherSuite

  /**
   * The single compression algorithm selected by the server from the list in ClientHello.
   *
   * compression_methods.
   */
  val compressionMethod: CompressionMethod

  /**
   * Constructs a full _ServerHello_ message. See [RFC 5246 (TLS 1.2), Section 7.4.1.3. Server Hello](https://tools.ietf.org/html/rfc5246#section-7.4.1.3) for details.
   *
   * @param version the negotiated version (highest supported by server).
   * @param sessionId the new session's identifier.
   * @param cipherSuite the negotiated cipher suite.
   * @param compressionMethod the negotiated compression method.
   * @throws NullPointerException if any of the parameters is `null`
   *
   */
  constructor(
    version: ProtocolVersion?,
    sessionId: SessionId?,
    cipherSuite: CipherSuite?,
    compressionMethod: CompressionMethod?,
  ) :
    super(version, sessionId) {
    requireNotNull(cipherSuite) { "Negotiated cipher suite must not be null" }
    requireNotNull(compressionMethod) { "Negotiated compression method must not be null" }
    this.cipherSuite = cipherSuite
    this.compressionMethod = compressionMethod
  }

  @Throws(HandshakeException::class)
  private constructor(reader: DatagramReader) : super(reader) {
    val code = reader.read(CipherSuite.CIPHER_SUITE_BITS)
    val cipherSuite = CipherSuite.getTypeByCode(code)
    if (cipherSuite == null) {
      throw HandshakeException(
        AlertMessage(
          AlertMessage.AlertLevel.FATAL,
          AlertMessage.AlertDescription.HANDSHAKE_FAILURE,
        ),
        "Server selected unknown cipher suite [%s]".format(Integer.toHexString(code)),
      )
    } else if (!cipherSuite.isValidForNegotiation) {
      throw HandshakeException(
        AlertMessage(
          AlertMessage.AlertLevel.FATAL,
          AlertMessage.AlertDescription.HANDSHAKE_FAILURE,
        ),
        "Server tries to negotiate a cipher suite invalid for negotiation",
      )
    }
    val compressionMethod = CompressionMethod.getMethodByCode(reader.read(CompressionMethod.COMPRESSION_METHOD_BITS))
    requireNotNull(compressionMethod) { "Compression Method must be set" }

    this.cipherSuite = cipherSuite
    this.compressionMethod = compressionMethod

    extensions.readFrom(reader)
  }

  override val messageType: HandshakeType
    get() = HandshakeType.SERVER_HELLO

  override val messageLength: Int
    get() {
      /*
       * fixed sizes: version (2) + random (32) + session ID length (1) +
       * cipher suite (2) + compression method (1) = 38
       * variable sizes: session ID, extensions
       */
      return 38 + sessionId.length() + extensions.length
    }

  override fun fragmentToByteArray(): ByteArray? {
    val writer = DatagramWriter()
    writeHeader(writer)

    writer.write(cipherSuite.code, CipherSuite.CIPHER_SUITE_BITS)
    writer.write(compressionMethod.code, CompressionMethod.COMPRESSION_METHOD_BITS)

    extensions.writeTo(writer)
    return writer.toByteArray()
  }

  override fun toString(indent: Int): String {
    return StringBuilder(super.toString(indent)).apply sb@{
      val indentation = Utility.indentation(indent + 1)
      this@sb.append(indentation).append("Cipher Suite: ").append(cipherSuite).append(Utility.LINE_SEPARATOR)
      this@sb.append(indentation).append("Compression Method: ").append(compressionMethod)
        .append(Utility.LINE_SEPARATOR)
      this@sb.append(extensions.toString(indent + 1))
    }.toString()
  }
}
