/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls

import io.kaxis.Bytes
import io.kaxis.dtls.message.*
import io.kaxis.dtls.message.handshake.*
import io.kaxis.exception.HandshakeException
import io.kaxis.util.DatagramWriter
import io.kaxis.util.NoPublicAPI
import io.kaxis.util.Utility
import org.slf4j.LoggerFactory
import java.net.DatagramPacket
import java.net.InetSocketAddress
import java.security.GeneralSecurityException

/**
 * A container for a set of DTLS records that are to be (re-)transmitted as a
 * whole on a DTLS connection.
 *
 * DTLS messages are grouped into a series of message flights. One flight
 * consists of at least one message and needs to be re-transmitted until the
 * peer's next flight has arrived in its total. A flight needs not only consist
 * of [HandshakeMessage]s but may also contain [AlertMessage]s and
 * [ChangeCipherSpecMessage]s. See [RFC 6347](https://tools.ietf.org/html/rfc6347#section-4.2.4) for details.
 */
@NoPublicAPI
class DTLSFlight {
  companion object {
    private val LOGGER = LoggerFactory.getLogger(DTLSFlight::class.java)

    /**
     * Increment the timeout, here we scale it, limited by the provided maximum.
     *
     * @param timeoutMillis timeout in milliseconds
     * @param scale scale factor
     * @param maxTimeoutMillis maximum timeout in milliseconds
     *
     * @return scaled and limited timeout in milliseconds
     */
    @JvmStatic
    fun incrementTimeout(
      timeoutMillis: Int,
      scale: Float,
      maxTimeoutMillis: Int,
    ): Int {
      var timeoutMillis0 = timeoutMillis
      if (timeoutMillis0 < maxTimeoutMillis) {
        timeoutMillis0 = Math.round(timeoutMillis0 * scale)
        timeoutMillis0 = timeoutMillis0.coerceAtMost(maxTimeoutMillis)
      }
      return timeoutMillis0
    }
  }

  /**
   * List of prepared records of flight.
   */
  val records: MutableList<Record>

  /**
   * The DTLS messages together with their epoch that belong to this flight.
   */
  val dtlsMessages: MutableList<EpochMessage>

  /**
   * The current DTLS context with the peer. Needed to set the record sequence number correctly when retransmitted.
   */
  val context: DTLSContext

  val peer: InetSocketAddress

  val peerToLog: Any?

  /**
   * The number of the flight.
   *
   * See RFC 6347, page 21.
   *
   * **Note**: `HelloVerifyRequest` sometimes used for resumption, therefore, the numbers are incremented!
   */
  val flightNumber: Int

  /**
   * The number of retransmissions.
   */
  var tries: Int = 0

  /**
   * The current timeout (in milliseconds).
   */
  var timeoutMillis: Int = 0

  /**
   * Maximum datagram size.
   */
  var maxDatagramSize: Int = 0

  /**
   * Maximum fragment size.
   */
  var maxFragmentSize: Int = 0

  /**
   * Effective maximum datagram size.
   *
   * The smaller resulting datagram size of [maxDatagramSize] and [maxFragmentSize]
   */
  var effectiveMaxDatagramSize: Int = 0

  /**
   * Effective maximum message size.
   *
   * The resulting message size of [maxDatagramSize] and [maxFragmentSize] and cipher suite.
   */
  var effectiveMaxMessageSize: Int = 0

  /**
   * Use DTLS records with multiple handshake messages.
   */
  var useMultiHandshakeMessageRecords: Boolean = false

  /**
   * Epoch of current [MultiHandshakeMessage].
   */
  var multiEpoch: Int = 0

  /**
   * Use CID for the current [MultiHandshakeMessage].
   */
  var multiUseCid: Boolean = false

  /**
   * Collect handshake messages for one DTLS record.
   */
  var multiHandshakeMessage: MultiHandshakeMessage? = null

  /**
   * Indicates, whether this flight needs retransmission. The very last flight (not every flight needs retransmission, e.g. Alert)
   */
  var retransmissionNeeded: Boolean = false

  /**
   * Indicates, whether this flight includes a [Finished] message or not.
   */
  var finishedIncluded: Boolean = false

  /**
   * Creates an empty flight to be sent within a session with a peer. Flights created using this constructor are
   * by default eligible for re-transmission.
   *
   * @param context the DTLS context to get record sequence numbers from when sending out the flight.
   * @param flightNumber number of the flight.
   * @param peer destination peer address.
   * @throws NullPointerException if context is `null`
   */
  constructor(context: DTLSContext?, flightNumber: Int, peer: InetSocketAddress) {
    requireNotNull(context) { "Session must not be null" }
    this.context = context
    this.peer = peer
    this.peerToLog = Utility.toLog(peer)
    this.records = arrayListOf()
    this.dtlsMessages = arrayListOf()
    this.retransmissionNeeded = true
    this.flightNumber = flightNumber
  }

  fun addDTLSMessage(
    epoch: Int,
    messageToAdd: DTLSMessage?,
  ) {
    requireNotNull(messageToAdd) { "message cannot be null!" }
    if (messageToAdd is Finished) {
      finishedIncluded = true
    }
    dtlsMessages.add(EpochMessage(epoch, messageToAdd))
  }

  /**
   * Get number of DTLS messages of this flight.
   *
   * @return number of DTLS messages
   */
  val numberOfMessages: Int
    get() = dtlsMessages.size

  /**
   * Check, if the provided message is contained in this flight.
   * @param message message to check
   * @return `true`, if message is contained, `false`, if not.
   */
  fun contains(message: DTLSMessage): Boolean {
    dtlsMessages.forEach { epochMessage ->
      if (message.toByteArray().contentEquals(epochMessage.message.toByteArray())) {
        return true
      }
    }
    return false
  }

  /**
   * Wraps a DTLS message into (potentially multiple) DTLS records and add them to the flight. Sets the
   * record's epoch, sequence number and handles fragmentation for handshake messages.
   *
   * @param epochMessage DTLS message and epoch
   * @throws HandshakeException if the message could not be encrypted using the session's current security parameters.
   */
  @Throws(HandshakeException::class)
  fun wrapMessage(epochMessage: EpochMessage) {
    try {
      val message = epochMessage.message
      when (val contentType = message.contentType) {
        ContentType.HANDSHAKE -> wrapHandshakeMessage(epochMessage)
        ContentType.CHANGE_CIPHER_SPEC -> {
          flushMultiHandshakeMessages()
          // CCS has only 1 byte payload and doesn't require fragmentation
          records.add(Record(message.contentType, epochMessage.epoch, message, context, false, 0))
          LOGGER.debug("Add CCS message of {} bytes for [{}]", message.size, peerToLog)
        }

        else -> throw HandshakeException(
          AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.INTERNAL_ERROR),
          "Cannot crate ${message.contentType} record for flight",
        )
      }
    } catch (e: GeneralSecurityException) {
      throw HandshakeException(
        AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.INTERNAL_ERROR),
        "Cannot create record",
        e,
      )
    }
  }

  /**
   * Wrap handshake messages into [MultiHandshakeMessage] or fragments, if handshake message is too large.
   *
   * The fragments needs to contain a fragment length and a fragment offset in order to combine the fragments
   * in the right order. The fragment length indicates the length of the data in this fragment, the fragment offset
   * indicates the length of the data in all previous fragments combined.
   *
   * ```
   *                                   +-------------------+
   *                                   |  TLS handshake    |
   *                                   +-------------------+
   *                                   | sequence_number=1 |
   *                                   +...................+
   *                                   | Data.length=1009  |
   *                                   |                   |
   *                                   |                   |
   *                                   |                   |
   *                                   +-------------------+
   *                                  /                     \
   *                                 /                       \
   *                                /                         \
   *                               /                           \
   *            +----------------------+                      +----------------------+
   *            | fragmented handshake |                      | fragmented handshake |
   *            +----------------------+                      +----------------------+
   *            | epoch=1              |                      | epoch=1              |
   *            | sequence_number=1    |                      | sequence_number=2    |
   *            +......................+                      +......................+
   *            | message_sequence=1   |                      | message_sequence=1   |
   *            | Data.length=1009     |                      | Data.length=1009     |
   *            | fragment_length=117  |                      | fragment_length=892  |
   *            | fragment_offset=0    |                      | fragment_offset=117  |
   *            +----------------------+                      +----------------------+
   *
   *
   * ```
   *
   * @param epochMessage handshake message and epoch
   * @throws GenericHandshakeMessage if the message could not be encrypted using the session's current security parameters.
   */
  @Throws(GeneralSecurityException::class)
  private fun wrapHandshakeMessage(epochMessage: EpochMessage) {
    val handshakeMessage = epochMessage.message as HandshakeMessage
    var maxPayloadLength = maxDatagramSize - Record.RECORD_HEADER_BYTES
    var effectiveMaxMessageSize: Int
    var useCid = false

    if (epochMessage.epoch > 0) {
      val connectionId = context.writeConnectionId
      if (connectionId != null && connectionId.isNotEmpty()) {
        useCid = true
        // reduce fragment length by connection id
        maxPayloadLength -= connectionId.length()
      }
    }

    if (maxFragmentSize >= maxPayloadLength) {
      effectiveMaxMessageSize = maxPayloadLength
      effectiveMaxDatagramSize = maxDatagramSize
    } else {
      effectiveMaxMessageSize = maxFragmentSize
      effectiveMaxDatagramSize = maxFragmentSize + (maxDatagramSize - maxPayloadLength)
    }

    if (epochMessage.epoch > 0) {
      effectiveMaxMessageSize -= context.session.maxCiphertextExpansion
      if (useCid) {
        // reduce message length by inner record type
        --effectiveMaxMessageSize
      }
    }

    this.effectiveMaxMessageSize = effectiveMaxMessageSize

    val messageSize = handshakeMessage.size

    if (messageSize <= effectiveMaxMessageSize) {
      if (useMultiHandshakeMessageRecords) {
        if (multiHandshakeMessage != null) {
          if (multiEpoch == epochMessage.epoch &&
            multiUseCid == useCid &&
            (multiHandshakeMessage?.size ?: (0 + messageSize)) < effectiveMaxMessageSize
          ) {
            multiHandshakeMessage?.add(handshakeMessage)
            LOGGER.debug(
              "Add multi-handshake-message {} message of {} bytes, resulting in {} bytes for [{}]",
              handshakeMessage.messageType,
              messageSize,
              multiHandshakeMessage?.messageLength,
              peerToLog,
            )
            return
          }
          flushMultiHandshakeMessages()
        }
        if (multiHandshakeMessage == null) {
          if (messageSize < effectiveMaxMessageSize) {
            multiHandshakeMessage = MultiHandshakeMessage()
            multiHandshakeMessage?.add(handshakeMessage)
            multiEpoch = epochMessage.epoch
            multiUseCid = useCid
            LOGGER.debug(
              "Start multi-handshake-message with {} message of {} bytes for [{}]",
              handshakeMessage.messageType,
              messageSize,
              peerToLog,
            )
            return
          }
        }
      }
      records.add(Record(ContentType.HANDSHAKE, epochMessage.epoch, handshakeMessage, context, useCid, 0))
      LOGGER.debug("Add {} message of {} bytes for [{}]", handshakeMessage.messageType, messageSize, peerToLog)

      return
    }

    flushMultiHandshakeMessages()

    // messages need to be fragmented
    LOGGER.debug(
      "Splitting up {} message of {} bytes for [{}] into multiple handshake fragments of max. {} bytes",
      handshakeMessage.messageType,
      messageSize,
      peerToLog,
      effectiveMaxMessageSize,
    )
    // create N handshake messages, all with the
    // same message_seq value as the original handshake message
    val messageBytes = handshakeMessage.fragmentToByteArray()
    requireNotNull(messageBytes) { "message fragment byte array cannot be null!" }
    val handshakeMessageLength = handshakeMessage.messageLength
    val maxHandshakeMessageLength = effectiveMaxMessageSize - HandshakeMessage.MESSAGE_HEADER_LENGTH_BYTES
    check(messageBytes.size == handshakeMessageLength) {
      "message length $handshakeMessageLength differs from message ${messageBytes.size}!"
    }
    val messageSeq = handshakeMessage.messageSeq
    var offset = 0
    while (offset < handshakeMessageLength) {
      var fragmentLength = maxHandshakeMessageLength
      if (offset + fragmentLength > handshakeMessageLength) {
        // the last fragment is normally shorter than the maximal size
        fragmentLength = handshakeMessageLength - offset
      }
      val fragmentBytes = ByteArray(fragmentLength)
      System.arraycopy(messageBytes, offset, fragmentBytes, 0, fragmentLength)

      val fragmentedMessage =
        FragmentedHandshakeMessage(
          handshakeMessage.messageType,
          handshakeMessageLength,
          messageSeq,
          offset,
          fragmentBytes,
        )

      LOGGER.debug("fragment for offset {}, {} bytes", offset, fragmentedMessage.size)

      offset += fragmentLength
      records.add(Record(ContentType.HANDSHAKE, epochMessage.epoch, fragmentedMessage, context, false, 0))
    }
  }

  /**
   * Wrap pending handshake messages in a DTLS record.
   *
   * @throws GeneralSecurityException if the message could not be encrypted using the session's current security parameters.
   */
  @Throws(GeneralSecurityException::class)
  private fun flushMultiHandshakeMessages() {
    if (multiHandshakeMessage != null) {
      records.add(Record(ContentType.HANDSHAKE, multiEpoch, multiHandshakeMessage, context, multiUseCid, 0))
      val count = multiHandshakeMessage?.numberOfHandshakeMessages ?: 0
      LOGGER.debug(
        "Add {} multi handshake message, epoch {} of {} bytes (max. {}) for [{}]",
        count,
        multiEpoch,
        multiHandshakeMessage?.messageLength ?: 0,
        effectiveMaxMessageSize,
        peerToLog,
      )
      multiHandshakeMessage = null
      multiEpoch = 0
      multiUseCid = false
    }
  }

  /**
   * Get wrapped records for the current flight.
   *
   * @param maxDatagramSize maximum datagram size
   * @param maxFragmentSize maximum fragment size
   * @param useMultiHandshakeMessageRecords enable to use DTLS records with multiple handshake messages
   *
   * @return list of records
   * @throws HandshakeException if the message could not be encrypted using the session's current security parameters
   */
  @Throws(HandshakeException::class)
  fun getRecords(
    maxDatagramSize: Int,
    maxFragmentSize: Int,
    useMultiHandshakeMessageRecords: Boolean,
  ): MutableList<Record> {
    try {
      if (this.maxDatagramSize == maxDatagramSize && this.maxFragmentSize == maxFragmentSize &&
        this.useMultiHandshakeMessageRecords == useMultiHandshakeMessageRecords
      ) {
        records.indices.forEach { index ->
          val record = records[index]
          val epoch = record.epoch
          val fragment = record.fragment
          val useCid = record.useConnectionId
          records[index] = Record(record.type, epoch, fragment, context, useCid, 0)
        }
      } else {
        this.effectiveMaxDatagramSize = maxDatagramSize
        this.maxDatagramSize = maxDatagramSize
        this.maxFragmentSize = maxFragmentSize
        this.useMultiHandshakeMessageRecords = useMultiHandshakeMessageRecords
        records.clear()
        dtlsMessages.forEach(this::wrapMessage)
        flushMultiHandshakeMessages()
      }
    } catch (e: GeneralSecurityException) {
      records.clear()
      throw HandshakeException(
        AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.INTERNAL_ERROR),
        "Cannot create record",
        e,
      )
    }
    return records
  }

  /**
   * List of datagrams to be sent for this flight.
   *
   * @param maxDatagramSize maximum datagram size
   * @param maxFragmentSize maximum fragment size
   * @param useMultiHandshakeMessageRecords enable to use DTLS records with multiple handshake messages
   * @param useMultiRecordMessages use datagrams with multiple DTLS records
   * @param backOff send flight in back off mode
   *
   * @return list of datagrams
   * @throws HandshakeException if the message could not be encrypted using the session's current security parameters.
   */
  @Suppress("kotlin:S3776")
  @Throws(HandshakeException::class)
  fun getDatagrams(
    maxDatagramSize: Int,
    maxFragmentSize: Int,
    useMultiHandshakeMessageRecords: Boolean?,
    useMultiRecordMessages: Boolean?,
    backOff: Boolean,
  ): MutableList<DatagramPacket> {
    var maxDatagramSize0 = maxDatagramSize

    val writer = DatagramWriter(maxDatagramSize0)

    val multiHandshakeMessages = useMultiHandshakeMessageRecords == true
    val multiRecords = useMultiRecordMessages != false

    if (backOff) {
      maxDatagramSize0 = (DEFAULT_IPV4_MTU - IPV4_HEADER_LENGTH).coerceAtMost(maxDatagramSize0)
    }

    LOGGER.trace(
      "Prepare flight {}, using max. datagram size {}, max. fragment size {} [mhm={}, mr={}]",
      flightNumber,
      maxDatagramSize0,
      maxFragmentSize,
      multiHandshakeMessages,
      multiRecords,
    )

    val records = getRecords(maxDatagramSize0, maxFragmentSize, multiHandshakeMessages)

    LOGGER.trace(
      "Effective max. datagram size {}, max. message size {}",
      effectiveMaxDatagramSize,
      effectiveMaxMessageSize,
    )

    // Re-Fragment records.
    val datagrams: MutableList<DatagramPacket> = mutableListOf()
    var index = 0
    while (index < records.size) {
      val record = records[index]

      var recordBytes = record.toByteArray()
      if (recordBytes.size > effectiveMaxDatagramSize) {
        LOGGER.error(
          "{} record of {} bytes for peer [{}] exceeds max. datagram size [{}], discarding...",
          record.type,
          recordBytes.size,
          peerToLog,
          effectiveMaxDatagramSize,
        )
        LOGGER.debug("{}", record)
        continue
      }
      LOGGER.trace("Sending record of {} bytes to peer [{}]:\n{}", recordBytes.size, peerToLog, record)
      if (multiRecords && record.type == ContentType.CHANGE_CIPHER_SPEC) {
        ++index
        if (index < records.size) {
          val finish = records[index]
          recordBytes = Bytes.concatenate(recordBytes, finish.toByteArray())
        }
      }
      val left =
        if (multiRecords && !(backOff && useMultiRecordMessages == null)) {
          effectiveMaxDatagramSize - recordBytes.size
        } else {
          0
        }
      if (writer.size() > left) {
        // the current record does not fit into datagram anymore
        val payload = writer.toByteArray()
        val datagram = DatagramPacket(payload, payload.size, peer.address, peer.port)
        datagrams.add(datagram)
        LOGGER.debug("Sending datagram of {} bytes to peer [{}]", payload.size, peerToLog)
      }
      writer.writeBytes(recordBytes)
      index++
    }

    val payload = writer.toByteArray()
    val datagram = DatagramPacket(payload, payload.size, peer.address, peer.port)
    datagrams.add(datagram)
    LOGGER.debug("Sending datagram of {} bytes to peer [{}]", payload.size, peerToLog)
    return datagrams
  }

  fun incrementTries() {
    this.tries++
  }

  /**
   * Called, when the flight needs to be retransmitted.
   *
   * Increment the timeout, scale it by the provided factor.
   *
   * Limit the timeout to the maximum timeout.
   *
   * @param scale timeout scale
   * @param maxTimeoutMillis maximum timeout
   * @see incrementTimeout
   */
  fun incrementTimeout(
    scale: Float,
    maxTimeoutMillis: Int,
  ) {
    this.timeoutMillis = incrementTimeout(this.timeoutMillis, scale, maxTimeoutMillis)
  }

  /**
   * DTLS message with epoch.
   * @param epoch epoch of message
   * @param message DTLS message
   */
  class EpochMessage(val epoch: Int, val message: DTLSMessage)
}
