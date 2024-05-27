/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.message

import io.kaxis.dtls.ContentType
import io.kaxis.dtls.DTLSMessage
import io.kaxis.dtls.HandshakeType
import io.kaxis.dtls.Handshaker
import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.dtls.message.handshake.*
import io.kaxis.exception.HandshakeException
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.NoPublicAPI
import io.kaxis.util.Utility
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Represents a general handshake message and defines the common header. The subclasses are responsible for
 * the rest of the message body. See [RFC 6347](https://tools.ietf.org/html/rfc6347#section-4.2.2) for the message format.
 */
@NoPublicAPI
abstract class HandshakeMessage : DTLSMessage {
  companion object {
    private val LOGGER: Logger = LoggerFactory.getLogger(HandshakeMessage::class.java)

    const val MESSAGE_TYPE_BITS = 8
    const val MESSAGE_LENGTH_BITS = 24
    const val MESSAGE_SEQ_BITS = 16
    const val FRAGMENT_OFFSET_BITS = 24
    const val FRAGMENT_LENGTH_BITS = 24
    const val MESSAGE_HEADER_LENGTH_BYTES =
      (
        MESSAGE_TYPE_BITS +
          MESSAGE_LENGTH_BITS +
          MESSAGE_SEQ_BITS +
          FRAGMENT_OFFSET_BITS +
          FRAGMENT_LENGTH_BITS
      ) / 8 // 12 bytes

    /**
     * Read handshake message from (received) byte array. Most handshake messages will be returned as specific subclass.
     * Only a few will be returned as [GenericHanshakeMessage] or [FragmentedHandshakeMessage]. If multiple hanshake
     * messages are contained, the returned handshake messages are chained by [nextHandshakeMessage].
     * @param byteArray byte array containing the handshake message
     * @return created handshake message
     * @throws HandshakeException if handshake message could not be used.
     */
    @Throws(HandshakeException::class)
    @JvmStatic
    fun fromByteArray(byteArray: ByteArray): HandshakeMessage? {
      try {
        var offset = 0
        var first: HandshakeMessage? = null
        var last: HandshakeMessage? = null
        val reader = DatagramReader(byteArray, false)
        do {
          val code = reader.read(MESSAGE_TYPE_BITS)
          val type =
            HandshakeType.getTypeByCode(code)
              ?: throw HandshakeException(
                AlertMessage(
                  AlertMessage.AlertLevel.FATAL,
                  AlertMessage.AlertDescription.UNEXPECTED_MESSAGE,
                ),
                "Cannot parse unsupported message type %d".format(code),
              )
          LOGGER.trace("Parsing HANDSHAKE message of type [{}]", type)
          val length = reader.read(MESSAGE_LENGTH_BITS)
          val messageSeq = reader.read(MESSAGE_SEQ_BITS)
          val fragmentOffset = reader.read(FRAGMENT_OFFSET_BITS)
          val fragmentLength = reader.read(FRAGMENT_LENGTH_BITS)

          val left = reader.bitsLeft() / Byte.SIZE_BITS
          if (fragmentLength > left) {
            throw HandshakeException(
              AlertMessage(
                AlertMessage.AlertLevel.FATAL,
                AlertMessage.AlertDescription.DECODE_ERROR,
              ),
              "Message %s fragment length %d exceeds available data %d".format(type, fragmentLength, left),
            )
          }
          val fragmentReader = reader.createRangeReader(fragmentLength)

          val start = offset
          offset = byteArray.size - (reader.bitsLeft() / Byte.SIZE_BITS)
          var body: HandshakeMessage
          if (length != fragmentLength) {
            if (fragmentOffset + fragmentLength > length) {
              throw HandshakeException(
                AlertMessage(
                  AlertMessage.AlertLevel.FATAL,
                  AlertMessage.AlertDescription.DECODE_ERROR,
                ),
                "Message %s fragment %d exceeds overall length %d".format(
                  type,
                  fragmentOffset + fragmentLength,
                  length,
                ),
              )
            }
            // fragmented message received
            body = FragmentedHandshakeMessage(type, length, messageSeq, fragmentOffset, fragmentReader.readBytesLeft())
          } else if (fragmentOffset != 0) {
            throw HandshakeException(
              AlertMessage(
                AlertMessage.AlertLevel.FATAL,
                AlertMessage.AlertDescription.DECODE_ERROR,
              ),
              "Message %s unexpected fragment offset".format(type),
            )
          } else {
            body =
              try {
                fromReader(type, fragmentReader)
              } catch (ex: MissingHandshakeParameterException) {
                GenericHandshakeMessage.fromByteArray(type)
              }
            // keep the raw bytes for computation of handshake hash
            body.rawMessage = byteArray.copyOfRange(start, offset)
            body.messageSeq = messageSeq
          }
          if (first == null) {
            first = body
          } else {
            last?.nextHandshakeMessage = body
          }
          last = body
        } while (reader.bytesAvailable())
        return first
      } catch (ex: IllegalArgumentException) {
        LOGGER.debug("Handshake message malformed", ex)
        throw HandshakeException(
          AlertMessage(
            AlertMessage.AlertLevel.FATAL,
            AlertMessage.AlertDescription.DECODE_ERROR,
          ),
          "Handshake message malformed, ${ex.message}",
        )
      }
    }

    /**
     * Create specific handshake from generic handshake message using the now available handshake parameter.
     * @param message generic handshake message
     * @param parameter handshake parameter
     * @return specific handshake message.
     * @throws HandshakeException if specific handshake message could not be created.
     */
    @Throws(HandshakeException::class)
    @JvmStatic
    fun fromGenericHandshakeMessage(
      message: GenericHandshakeMessage,
      parameter: HandshakeParameter,
    ): HandshakeMessage {
      try {
        val type = message.messageType
        LOGGER.trace("Parsing HANDSHAKE message of type [{}]", type)
        val byteArray = message.toByteArray()
        val reader = DatagramReader(message.fragmentToByteArray(), false)

        val body = fromReader(type, reader, parameter)

        // keep the raw bytes for computation of handshake hash
        body.rawMessage = byteArray
        body.messageSeq = message.messageSeq
        body.nextHandshakeMessage = message.nextHandshakeMessage

        return body
      } catch (e: IllegalArgumentException) {
        LOGGER.debug("Handshake message malformed", e)
        throw HandshakeException(
          AlertMessage(
            AlertMessage.AlertLevel.FATAL,
            AlertMessage.AlertDescription.DECODE_ERROR,
          ),
          "Handshake message malformed, ${e.message}",
        )
      }
    }

    /**
     * Create handshake message from reader. If the handshake parameter are available, a specific handshake message is returned.
     * If not, a [GenericHandshakeMessage] or [FragmentedHandshakeMessage] may be returned.
     * @param type type of handshake message
     * @param reader reader to read message
     * @param parameter handshake parameter
     * @return handshake message
     * @throws HandshakeException if handshake message could not be created.
     */
    @Throws(HandshakeException::class)
    @JvmStatic
    fun fromReader(
      type: HandshakeType,
      reader: DatagramReader,
      parameter: HandshakeParameter? = null,
    ): HandshakeMessage {
      val body =
        when (type) {
          HandshakeType.HELLO_REQUEST -> HelloRequest()
          HandshakeType.CLIENT_HELLO -> ClientHello.fromReader(reader)
          HandshakeType.SERVER_HELLO -> ServerHello.fromReader(reader)
          HandshakeType.HELLO_VERIFY_REQUEST -> HelloVerifyRequest.fromReader(reader)
          HandshakeType.CERTIFICATE -> {
            if (parameter == null) {
              throw MissingHandshakeParameterException("HandshakeParameter must not be null!")
            }
            return CertificateMessage.fromReader(reader, parameter.certificateType)
          }

          HandshakeType.SERVER_KEY_EXCHANGE -> {
            if (parameter == null) {
              throw MissingHandshakeParameterException("HandshakeParameter must not be null!")
            }
            return readServerKeyExchange(reader, parameter.keyExchangeAlgorithm)
          }

          HandshakeType.CERTIFICATE_REQUEST -> CertificateRequest.fromReader(reader)
          HandshakeType.SERVER_HELLO_DONE -> ServerHelloDone()
          HandshakeType.CERTIFICATE_VERIFY -> CertificateVerify.fromReader(reader)
          HandshakeType.CLIENT_KEY_EXCHANGE -> {
            if (parameter == null) {
              throw MissingHandshakeParameterException("HandshakeParameter must not be null!")
            }
            return readClientKeyExchange(reader, parameter.keyExchangeAlgorithm)
          }

          HandshakeType.FINISHED -> Finished.fromReader(reader)
          else -> throw HandshakeException(
            AlertMessage(
              AlertMessage.AlertLevel.FATAL,
              AlertMessage.AlertDescription.UNEXPECTED_MESSAGE,
            ),
            "Cannot parse unsupported message type %s".format(type),
          )
        }
      if (reader.bytesAvailable()) {
        val bytesLeft = reader.bitsLeft() / Byte.SIZE_BITS
        throw HandshakeException(
          AlertMessage(
            AlertMessage.AlertLevel.FATAL,
            AlertMessage.AlertDescription.DECODE_ERROR,
          ),
          "Too many bytes, %d left, message not completely parsed! message type %s".format(bytesLeft, type),
        )
      }
      return body
    }

    /**
     * Read server key exchange message.
     * @param reader reader with data
     * @param keyExchange key exchange algorithm
     * @return key exchange handshake message
     * @throws HandshakeException if handshake message could not be created
     */
    @Throws(HandshakeException::class)
    @JvmStatic
    fun readServerKeyExchange(
      reader: DatagramReader,
      keyExchange: CipherSuite.KeyExchangeAlgorithm,
    ): HandshakeMessage {
      return when (keyExchange) {
        CipherSuite.KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN -> EcdhSignedServerKeyExchange.fromReader(reader)
        CipherSuite.KeyExchangeAlgorithm.PSK -> PskServerKeyExchange.fromReader(reader)
        CipherSuite.KeyExchangeAlgorithm.ECDHE_PSK -> EcdhPskServerKeyExchange.fromReader(reader)
        else -> throw HandshakeException(
          AlertMessage(
            AlertMessage.AlertLevel.FATAL,
            AlertMessage.AlertDescription.ILLEGAL_PARAMETER,
          ),
          "Unsupported key exchange algorithm",
        )
      }
    }

    /**
     * Read client key exchange message.
     * @param reader reader with data
     * @param keyExchange key exchange algorithm
     * @return key exchange handshake message
     * @throws HandshakeException if handshake message could not be created
     */
    @Throws(HandshakeException::class)
    @JvmStatic
    fun readClientKeyExchange(
      reader: DatagramReader,
      keyExchange: CipherSuite.KeyExchangeAlgorithm,
    ): HandshakeMessage {
      return when (keyExchange) {
        CipherSuite.KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN -> ECDHClientKeyExchange.fromReader(reader)
        CipherSuite.KeyExchangeAlgorithm.PSK -> PskClientKeyExchange.fromReader(reader)
        CipherSuite.KeyExchangeAlgorithm.ECDHE_PSK -> EcdhPskClientKeyExchange.fromReader(reader)
        else -> throw HandshakeException(
          AlertMessage(
            AlertMessage.AlertLevel.FATAL,
            AlertMessage.AlertDescription.ILLEGAL_PARAMETER,
          ),
          "Unknown key exchange algorithm",
        )
      }
    }
  }

  /**
   * Whenever each message is assigned to a flight, the message_seq is set with an incremented value from the [Handshaker]
   */
  open var messageSeq: Int = 0
    set(messageSeq) {
      check(byteArray == null) { "message is already serialized!" }
      require(messageSeq in 0..0xffff) { "Handshake message sequence number $messageSeq out of range [0...65535]!" }
      field = messageSeq
    }

  /**
   * Used to store the raw incoming message this instance has been created from. Only set if this message has been received from
   *  another peer. The `rawMessage` is used to calculate the hash/message digest value sent in the `Finished` message.
   */
  @Volatile
  var rawMessage: ByteArray? = null

  /**
   * Used to store the raw message of this instance. Set either by the received raw message on incoming
   * messages, or by the generated message for outgoing messages. If the payload (fragment) of an outgoing
   * message is changed, it's required to reset this field by calling [fragmentChanged]
   */
  @Volatile
  var byteArray: ByteArray? = null

  /**
   * Next handshake message received with the dtls record. `null`, if no additional handshake message is received.
   */
  var nextHandshakeMessage: HandshakeMessage? = null

  /**
   * Returns the type of the handshake message. See [HandshakeType].
   */
  abstract val messageType: HandshakeType

  /**
   * Must be implemented by each subclass. The length is given in bytes and only includes the length of the subclass'
   * specific fields (not the handshake message header).
   * @return the length of the message **in bytes**.
   */
  abstract val messageLength: Int

  /**
   * The serialization of the handshake body (without the handshake header). Must be implemented by each
   * subclass. Except the [ClientHello], the fragments are considered to be not modified. If a modification is
   * required, call [fragmentChanged].
   * @return the raw byte representation of the handshake body.
   */
  abstract fun fragmentToByteArray(): ByteArray?

  override val contentType: ContentType = ContentType.HANDSHAKE

  /**
   * Gets the implementation type prefix for logging.
   * @return implementation type prefix.
   */
  open val implementationTypePrefix: String = ""

  /**
   * Reset the [byteArray] in order to generate an outgoing raw message with the changed payload/fragment.
   * Only used by [ClientHello.setCookie].
   */
  fun fragmentChanged() {
    byteArray = null
  }

  open val fragmentOffset: Int
    get() = 0

  open val fragmentLength: Int
    get() = messageLength

  override val size: Int
    get() = fragmentLength + MESSAGE_HEADER_LENGTH_BYTES

  /**
   * Returns the raw binary representation of the handshake message. For incoming messages this it the same
   * as [rawMessage]. For outgoing messages the header is generated by this method and the subclasses
   * are responsible for the specific rest of the payload / fragment. The result is only created once at the first
   * call. Following calls will get the same bytes util [fragmentChanged] gets called.
   * @return the byte representation of the handshake message.
   */
  override fun toByteArray(): ByteArray? {
    if (rawMessage != null) {
      return rawMessage
    }
    if (byteArray == null) {
      // create datagram writer to encode message data
      val fragmentLength = fragmentLength
      val writer = DatagramWriter(fragmentLength + MESSAGE_HEADER_LENGTH_BYTES)
      writeTo(writer)
      byteArray = writer.toByteArray()
    }

    return byteArray
  }

  /**
   * Write handshake message to writer.
   * @param writer writer to write handshake message.
   */
  fun writeTo(writer: DatagramWriter) {
    // write fixed-size handshake message header
    writer.write(messageType.code, MESSAGE_TYPE_BITS)
    writer.write(messageLength, MESSAGE_LENGTH_BITS)
    writer.write(messageSeq, MESSAGE_SEQ_BITS)
    writer.write(fragmentOffset, FRAGMENT_OFFSET_BITS)
    writer.write(fragmentLength, FRAGMENT_LENGTH_BITS)
    writer.writeBytes(fragmentToByteArray())
  }

  override fun toString(indent: Int): String {
    return StringBuilder().apply sb@{
      val indentation = Utility.indentation(indent)
      this@sb.append(indentation).append(implementationTypePrefix).append("Handshake Message")
        .append(Utility.LINE_SEPARATOR)
      this@sb.append(indentation).append("Type: ").append(messageType).append(Utility.LINE_SEPARATOR)
      this@sb.append(indentation).append("Message Sequence No: ").append(messageSeq).append(Utility.LINE_SEPARATOR)
      this@sb.append(indentation).append("Length: ").append(messageLength).append(" bytes")
        .append(Utility.LINE_SEPARATOR)
    }.toString()
  }

  override fun toString(): String {
    return toString(0)
  }

  /**
   * Exception on missing [HandshakeParameter].
   */
  class MissingHandshakeParameterException(message: String? = null) : IllegalArgumentException(message)
}
