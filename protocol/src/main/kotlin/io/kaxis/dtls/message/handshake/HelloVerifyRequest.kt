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

import io.kaxis.dtls.HandshakeType
import io.kaxis.dtls.ProtocolVersion
import io.kaxis.dtls.message.HandshakeMessage
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility

/**
 * The server sends this request after receiving a [ClientHello] message to prevent Denial-of_Service Attacks.
 *
 * See [RFC 6347](https://tools.ietf.org/html/rfc6347#section-4.2.1) for the definition.
 *
 * ```
 *   Client                                   Server
 *   ------                                   ------
 *   ClientHello           ----->
 *
 *                         <----- HelloVerifyRequest
 *                                 (contains cookie)
 *
 *   ClientHello           ----->
 *   (with cookie)
 *
 *   [Rest of handshake] *
 *
 * ```
 * It seems that this definition is ambiguous about the server version to be used.
 *
 * ```
 * The server_version field...
 * DTLS 1.2 server implementations SHOULD use DTLS version 1.0 regardless
 * of the version of TLS that is expected to be negotiated. ...
 * The server MUST use the same version number in the HelloVerifyRequest
 * that it would use when sending a ServerHello. ...
 * ```
 *
 * A DTLS 1.2 server can either (SHOULD) send a version 1.0, or (MUST use same version) 1.2. This question is
 * pending in the IETF TLS mailing list, see [RFC 6347 - Section 4.2.1 - used version in a HelloVerifyRequest](https://mailarchive.ietf.org/arch/msg/tls/rQ3El3ROKTN0rpzhRpJCaKOrUyU/).
 *\
 * There may be many assumptions about the intended behavior. The one implemented is to postpone the version
 * negotiation according [RFC 5246 - E.1 - Compatibility with TLS 1.0/1.1 and SSL 3.0]()
 * until the endpoint ownership is verified. That prevents sending protocol-version alerts to wrong clients. Therefore,
 * the server tries to use the client version in the HELLO_VERIFY_REQUEST, and once a CLIENT_HELLO with the proper
 * cookie is received, a protocol-version alert is sent back.
 *
 * If interoperability is required, a client MUST comply with the definition there:
 * ```
 * DTLS 1.2 and 1.0 clients MUST use the version solely to
 * indicate packet formatting (which is the same in both DTLS 1.2 and
 * 1.0) and not as part of version because the server uses version 1.0 in
 * the HelloVerifyRequest that the server is not DTLS 1.2 or that it
 * will eventually negotiate DTLS 1.0 rather than DTLS 1.2.
 * ```
 */
class HelloVerifyRequest : HandshakeMessage {
  companion object {
    private const val VERSION_BITS = 8 // for major and minor each

    private const val COOKIE_LENGTH_BITS = 8

    @JvmStatic
    fun fromReader(reader: DatagramReader): HelloVerifyRequest {
      val major = reader.read(VERSION_BITS)
      val minor = reader.read(VERSION_BITS)
      val version = ProtocolVersion.valueOf(major, minor)
      val cookie = reader.readBytes(COOKIE_LENGTH_BITS)
      return HelloVerifyRequest(version, cookie)
    }
  }

  /**
   * This field will contain the lowest of that suggested by the client in the client hello and the highest
   * supported by the server.
   */
  val serverVersion: ProtocolVersion

  /**
   * The cookie which needs to be replayed by the client.
   */
  val cookie: ByteArray

  constructor(version: ProtocolVersion, cookie: ByteArray) {
    this.serverVersion = version
    this.cookie = cookie
  }

  override val messageType: HandshakeType
    get() = HandshakeType.HELLO_VERIFY_REQUEST

  override val messageLength: Int
    get() {
      // fixed: version (2) + cookie length (1)
      return 3 + cookie.size
    }

  override fun fragmentToByteArray(): ByteArray? {
    val writer = DatagramWriter(cookie.size + 3)

    writer.write(serverVersion.major, VERSION_BITS)
    writer.write(serverVersion.minor, VERSION_BITS)

    writer.writeVarBytes(cookie, COOKIE_LENGTH_BITS)
    return writer.toByteArray()
  }

  override fun toString(indent: Int): String {
    return StringBuilder(super.toString(indent)).apply sb@{
      val indentation = Utility.indentation(indent + 1)
      this@sb.append(indentation).append("Server Version: ").append(serverVersion.major).append(", ")
        .append(serverVersion.minor).append(Utility.LINE_SEPARATOR)
      this@sb.append(indentation).append("Cookie Length: ").append(cookie.size).append(" bytes")
        .append(Utility.LINE_SEPARATOR)
      this@sb.append(indentation).append("Cookie: ").append(Utility.byteArray2HexString(cookie))
        .append(Utility.LINE_SEPARATOR)
    }.toString()
  }
}
