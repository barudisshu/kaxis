/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.extensions

import io.kaxis.dtls.ServerNames
import io.kaxis.dtls.message.AlertMessage
import io.kaxis.exception.HandshakeException
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility

/**
 * Conveys information specified by the _Server Name Indication_ TLS extension. See [RFC 6066, Section 3](https://tools.ietf.org/html/rfc6066#section-3) for additional details.
 */
class ServerNameExtension(val serverNames: ServerNames?) : HelloExtension(ExtensionType.SERVER_NAME) {
  companion object {
    private val EMPTY_SERVER_NAMES = ServerNameExtension(null)

    /**
     * Creates a new empty Server Name Indication extension.
     *
     * This method should be used by a server that wants to include an empty _Server Name Indication_ extension in its
     * _SERVER_HELLO_ handshake message.
     */
    fun emptyServerNameIndication(): ServerNameExtension = EMPTY_SERVER_NAMES

    /**
     * Creates a new instance for a server name list.
     *
     * This constructor should be used by a client who wants to include the _Server Name Indication_ extension in
     * its _CLIENT_HELLO_ handshake message.
     * @param serverNames server names
     * @return new instance
     * @throws NullPointerException if the server name list is `null`.
     * @throws IllegalArgumentException if the server name list is empty.
     */
    fun forServerNames(serverNames: ServerNames?): ServerNameExtension {
      requireNotNull(serverNames) { "server names must not be null" }
      require(serverNames.size != 0) { "server names must not be empty" }
      return ServerNameExtension(serverNames)
    }

    /**
     * Creates a new instance from its byte representation.
     * @param extensionDataReader the byte representation.
     * @return the instance.
     * @throws HandshakeException if the byte representation could not be parsed.
     */
    @Throws(HandshakeException::class)
    fun fromExtensionDataReader(extensionDataReader: DatagramReader): ServerNameExtension {
      if (!extensionDataReader.bytesAvailable()) {
        // this is an "empty" Server Name Indication received in a SERVER_HELLO
        return emptyServerNameIndication()
      } else {
        val serverNames = ServerNames.newInstance()
        try {
          serverNames.decode(extensionDataReader)
        } catch (e: IllegalArgumentException) {
          if (e.cause is IllegalArgumentException) {
            throw HandshakeException(
              AlertMessage(
                AlertMessage.AlertLevel.FATAL,
                AlertMessage.AlertDescription.ILLEGAL_PARAMETER,
              ),
              "Server Name Indication extension contains unknown name_type",
            )
          }
          throw HandshakeException(
            AlertMessage(
              AlertMessage.AlertLevel.FATAL,
              AlertMessage.AlertDescription.DECODE_ERROR,
            ),
            "malformed Server Name Indication extension",
          )
        }
        return ServerNameExtension(serverNames)
      }
    }
  }

  override fun toString(indent: Int): String {
    var text = super.toString(indent)
    if (serverNames != null) {
      text = text + serverNames.toString(indent + 1) + Utility.LINE_SEPARATOR
    }
    return text
  }

  override val extensionLength: Int
    get() {
      return serverNames?.length ?: 0
    }

  override fun writeExtensionTo(writer: DatagramWriter) {
    serverNames?.encode(writer)
  }
}
