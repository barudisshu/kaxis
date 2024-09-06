/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls

import io.kaxis.Bytes
import io.kaxis.util.*
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.InvalidKeyException
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.security.auth.Destroyable
import kotlin.math.max

/**
 * Represents a DTLS context between two peers. Keeps track of the current and pending read/write states, the
 * current epoch and sequence number, etc. Contains the keys and the [DTLSSession].
 */
class DTLSContext : Destroyable {
  companion object {
    private val LOGGER: Logger = LoggerFactory.getLogger(DTLSContext::class.java)

    private const val RECEIVE_WINDOW_SIZE = 64

    /**
     * Version number for serialization.
     */
    private const val VERSION = 4

    /**
     * Version number for serialization before introducing [useDeprecatedCid]
     */
    private const val VERSION_DEPRECATED = 2

    /**
     * Version number for serialization before introducing [useDeprecatedCid]
     */
    private const val VERSION_DEPRECATED_2 = 3

    private val VERSIONS = SerializationUtil.SupportedVersionsMatcher(VERSION, VERSION_DEPRECATED, VERSION_DEPRECATED_2)

    /**
     * Read DTLS context state.
     * @param reader reader with DTLS context state.
     * @return read DTLS context.
     * @throws IllegalArgumentException if version differs or the data is erroneous
     */
    @JvmStatic
    fun fromReader(reader: DatagramReader): DTLSContext? {
      val matcher = VERSIONS.matcher()
      val length = SerializationUtil.readStartItem(reader, matcher, Short.SIZE_BITS)
      return if (0 < length) {
        val rangeReader = reader.createRangeReader(length)
        DTLSContext(matcher.readVersion, rangeReader)
      } else {
        null
      }
    }

    /**
     * Version number of sequence-number serialization.
     */
    private const val SEQN_VERSION = 1
  }

  /**
   * Use deprecated MAC for CID.
   */
  var useDeprecatedCid: Boolean = false

  /**
   * Connection id used for all outbound records.
   */
  var writeConnectionId: ConnectionId? = null

  /**
   * Connection id used for all inbound records.
   */
  var readConnectionId: ConnectionId? = null

  /**
   * The _current read state_ used for processing all inbound records.
   */
  var readState: DTLSConnectionState = DTLSConnectionState.NULL

  /**
   * The _current write state_ used for processing all outbound.
   */
  var writeState: DTLSConnectionState = DTLSConnectionState.NULL
    get() {
      return if (writeEpoch == 0) {
        DTLSConnectionState.NULL
      } else {
        field
      }
    }

  fun getWriteState(epoch: Int): DTLSConnectionState = if (epoch == 0) DTLSConnectionState.NULL else writeState

  /**
   * Write key for cluster internal communication.
   */
  var clusterWriteMacKey: SecretKey? = null

  /**
   * Read key for cluster internal communication.
   */
  var clusterReadMacKey: SecretKey? = null

  /**
   * Indicates, if support for key material export is enabled.
   */
  val supportExport: Boolean

  /**
   * Client random.
   *
   * Only available, if [DTLS_SUPPORT_KEY_MATERIAL_EXPORT] is enabled.
   */
  var clientRandom: Random? = null

  /**
   * Server random.
   *
   * Only available, if [DTLS_SUPPORT_KEY_MATERIAL_EXPORT] is enabled.
   */
  var serverRandom: Random? = null

  /**
   * The current read epoch, incremented with every _CHANGE_CIPHER_SPEC_ message received.
   */
  var readEpoch: Int = 0
    set(epoch) {
      require(epoch >= 0) { "Read epoch must not be negative" }
      resetReceiveWindow()
      field = epoch
    }

  fun incrementReadEpoch() {
    resetReceiveWindow()
    this.readEpoch++
  }

  /**
   * The current read epoch, incremented with every _CHANGE_CIPHER_SPEC_ message sent.
   */
  var writeEpoch: Int = 0

  private fun incrementWriteEpoch() {
    this.writeEpoch++
    // Sequence numbers are maintained separately for each epoch, with each
    // sequence_number initially being 0 for each epoch.
    this.sequenceNumbers[writeEpoch] = 0L
  }

  /**
   * The effective fragment size.
   */
  var effectiveMaxMessageSize: Int = 0

  // We only need 2 values as we do not support DTLS re-negotiation.
  private val sequenceNumbers: LongArray = LongArray(2)

  /**
   * Gets the smallest unused sequence number for outbound records for a given epoch.
   *
   * @param epoch the epoch for which to get the sequence number
   * @return the next sequence number
   * @throws IllegalStateException if the maximum sequence number for the epoch has been reached (2^48 - 1)
   */
  fun getNextSequenceNumber(epoch: Int = writeEpoch): Long {
    val sequenceNumber = this.sequenceNumbers[epoch]

    if (sequenceNumber <= Record.MAX_SEQUENCE_NO) {
      this.sequenceNumbers[epoch] = sequenceNumber + 1
      return sequenceNumber
    } else {
      // maximum sequence number has been reached
      // see section 4.1 of RFC 6347 (DTLS 1.2)
      error("Maximum sequence number for epoch has been reached")
    }
  }

  /**
   * Create the current read state of the connection. The information in the current read state is used to decrypt
   * messages received from a peer. See [RFC 5246(TLS 1.2)](https://tools.ietf.org/html/rfc5246#section-6.1) for details.
   *
   * The _pending_ read state becomes the _current_ read state whenever a _CHANGE_CIPHER_SPEC_ message is received from
   * a peer during a handshake.
   *
   * This method also increments the read epoch.
   * @param encryptionKey the secret key to use for decrypting message content
   * @param iv the initialization vector to use for decrypting message content
   * @param macKey the key to use for verifying message authentication codes (MAC)
   * @throws NullPointerException if any of the parameter used by the provided cipher suite is `null`
   */
  fun createReadState(
    encryptionKey: SecretKey?,
    iv: SecretIvParameterSpec?,
    macKey: SecretKey?,
  ) {
    val readState =
      DTLSConnectionState.create(session.cipherSuite, session.compressionMethod, encryptionKey, iv, macKey)
    SecretUtil.destroy(this.readState)
    this.readState = readState
    incrementReadEpoch()
    LOGGER.trace("Setting current read state to{}{}", Utility.LINE_SEPARATOR, readState)
  }

  val readStateCipher: String
    /**
     * Gets the name of the current read state's cipher state.
     */
    get() = readState.cipherSuite.name

  /**
   * Create the current write state of the connection. The information in the current write state is used to encrypt
   * messages sent to a peer. See [RFC 5246(TLS 1.2)](https://tools.ietf.org/html/rfc5246#section-6.1) for details.
   *
   * The _pending_ write state becomes hte _current_ write state whenever a _CHANGE_CIPHER_SPEC_ message is sent to
   * a peer during a handshake.
   *
   * This method also increments the write epoch and resets the session's sequence number counter to zero.
   * @param encryptionKey the secret key to use for encrypting message content
   * @param iv the initialization vector to use for encrypting message content
   * @param macKey the key to use for creating message authentication codes (MAC)
   * @throws NullPointerException if any of the parameter used by the provided cipher suite is `null`
   */
  fun createWriteState(
    encryptionKey: SecretKey?,
    iv: SecretIvParameterSpec?,
    macKey: SecretKey?,
  ) {
    val writeState =
      DTLSConnectionState.create(session.cipherSuite, session.compressionMethod, encryptionKey, iv, macKey)
    SecretUtil.destroy(this.writeState)
    this.writeState = writeState
    incrementWriteEpoch()
    LOGGER.trace("Setting current write state to{}{}", Utility.LINE_SEPARATOR, writeState)
  }

  val writeStateCipher: String
    /**
     * Gets the name of the current write state's cipher suite.
     * @return the name.
     */
    get() = writeState.cipherSuite.name

  /**
   * Checks whether a given record can be processed within this DTLS context. This is the case if:
   * - the record is from the same epoch as DTLS context's current read epoch
   * - the record has not been received before
   * - if marked as closed, the record's sequence number is not after the close_notify's sequence number
   * @param epoch the record's epoch
   * @param sequenceNo the record's sequence number
   * @param useExtendedWindow this value will be subtracted from to lower receive window boundary.
   * A value of `-1` will set that calculated value to `0`. Messages between lower receive window
   * boundary and that calculated value will pass the filter, for other messages the filter is applied.
   * @return `true` if the record satisfies the conditions above
   * @throws IllegalArgumentException if the epoch differs from the current read epoch
   *
   */
  fun isRecordProcessable(
    epoch: Int,
    sequenceNo: Long,
    useExtendedWindow: Int,
  ): Boolean {
    val readEpoch = readEpoch
    require(epoch == readEpoch) { "wrong epoch! $epoch != $readEpoch" }
    if (sequenceNo < receiveWindowLowerBoundary) {
      // record lies out of receive window's "left" edge discard
      if (useExtendedWindow < 0) {
        // within extended window => pass
        return true
      } else {
        // within extended window? => pass
        return sequenceNo > receiveWindowLowerBoundary - useExtendedWindow
      }
    } else if (markedAsClosed) {
      if (epoch > readEpochClosed) {
        // record after close
        return false
      } else if (epoch == readEpochClosed && sequenceNo >= readSequenceNumberClosed) {
        // record after close
        return false
      }
      // otherwise, check for duplicate
    }
    return !isDuplicate(sequenceNo)
  }

  /**
   * Checks, whether a given record has already been received during the current epoch.
   *
   * The check is done based on a _sliding window_ as described in [section 4.1.2.6 of the DTLS 1.2 spec](https://tools.ietf.org/html/rfc6347#section-4.1.2.6).
   *
   * @param sequenceNo the record's sequence number
   * @return `true`, if the record has already been received
   */
  protected fun isDuplicate(sequenceNo: Long): Boolean {
    return if (sequenceNo > receiveWindowUpperCurrent) {
      false
    } else {
      // determine (zero based) index of record's sequence number within receive window
      val idx = sequenceNo - receiveWindowLowerBoundary
      // create bit mask for probing the bit representing position "idx"
      val bitMask = 1L shl idx.toInt()
      if (LOGGER.isDebugEnabled) {
        LOGGER.debug(
          "Checking sequence no [{}] using bit mask [{}] against received records [{}] with lower boundary [{}]",
          sequenceNo,
          java.lang.Long.toBinaryString(bitMask),
          java.lang.Long.toBinaryString(receivedRecordsVector),
          receiveWindowLowerBoundary,
        )
      }
      (receivedRecordsVector and bitMask) == bitMask
    }
  }

  /**
   * Marks a record as having been received so that it can be detected as a duplicate if it is received again, e.g.
   *
   * If a client re-transmits the record because it runs into a timeout. The record is marked as received only, if it
   * belongs to the DTLS context's current read epoch as indicated by [readEpoch]
   *
   * @param epoch the record's epoch
   * @param sequenceNo  the record's sequence number
   * @return `true`, if the epoch/sequenceNo is newer than the current newest. `false`, if not.
   * @throws IllegalArgumentException if the epoch differs from the current read epoch.
   */
  fun markRecordAsRead(
    epoch: Int,
    sequenceNo: Long,
  ): Boolean {
    val readEpoch = readEpoch
    require(epoch == readEpoch) { "wrong epoch! $epoch != $readEpoch" }
    val newest = sequenceNo > receiveWindowUpperCurrent
    if (newest) {
      receiveWindowUpperCurrent = sequenceNo
      val lowerBoundary = max(0, sequenceNo - RECEIVE_WINDOW_SIZE + 1)
      val incr = lowerBoundary - receiveWindowLowerBoundary
      if (incr > 0) {
        // slide receive window to the right
        receivedRecordsVector = receivedRecordsVector ushr incr.toInt()
        receiveWindowLowerBoundary = lowerBoundary
      }
    }
    val bitMask = 1L shl (sequenceNo - receiveWindowLowerBoundary).toInt()
    // mark sequence number as "received" in receive window
    receivedRecordsVector = receivedRecordsVector or bitMask
    if (LOGGER.isDebugEnabled) {
      LOGGER.debug(
        "Updated receive window with sequence number [{}]: new upper boundary [{}], new bit vector [{}]",
        sequenceNo,
        receiveWindowUpperCurrent,
        java.lang.Long.toBinaryString(receivedRecordsVector),
      )
    }
    return newest
  }

  /**
   * Save close_notify
   */
  private var readEpochClosed: Int = 0
  private var readSequenceNumberClosed: Long = 0

  /**
   * DTLS context is marked as close
   */
  private var markedAsClosed: Boolean = false

  /**
   * Mark as closed. If a DTLS context is marked as closed, no records should be sent and no received newer records
   * should be processed.
   *
   * @param epoch epoch of close notify
   * @param sequenceNo sequence number of close notify
   */
  fun markCloseNotify(
    epoch: Int,
    sequenceNo: Long,
  ) {
    markedAsClosed = true
    readEpochClosed = epoch
    readSequenceNumberClosed = sequenceNo
  }

  @Volatile
  private var receiveWindowUpperCurrent: Long = -1

  @Volatile
  private var receiveWindowLowerBoundary: Long = 0

  @Volatile
  private var receivedRecordsVector: Long = 0

  /**
   * Re-initializes the received window to detect duplicates for a new epoch.
   *
   * The received window is reset to sequence number zero and all information
   * about received records is cleared.
   */
  private fun resetReceiveWindow() {
    receivedRecordsVector = 0
    receiveWindowUpperCurrent = -1
    receiveWindowLowerBoundary = 0
  }

  @Volatile
  private var macErrors: Long = 0

  /**
   * Increment the number of MAC errors (including general encryption errors).
   */
  fun incrementMacErrors() {
    ++macErrors
  }

  // The Final variable isn't changed.
  val handshakeTime: Long

  var session: DTLSSession

  /**
   * Set mac-keys for cluster communication
   * @param clusterWriteMacKey write mac-key
   * @param clusterReadMacKey read mac-key
   */
  fun setClusterMacKeys(
    clusterWriteMacKey: SecretKey,
    clusterReadMacKey: SecretKey,
  ) {
    this.clusterWriteMacKey = SecretUtil.create(clusterWriteMacKey)
    this.clusterReadMacKey = SecretUtil.create(clusterReadMacKey)
  }

  /**
   * Get thread local cluster write MAC. Initialize the MAc with the [clusterWriteMacKey].
   * @return thread local cluster write MAC, or `null`, if not available.
   */
  val threadLocalClusterWriteMac: Mac?
    get() {
      if (clusterWriteMacKey != null) {
        try {
          val mac = session.cipherSuite.threadLocalPseudoRandomFunctionMac
          mac?.init(clusterWriteMacKey)
          return mac
        } catch (e: InvalidKeyException) {
          LOGGER.info("cluster write MAC error", e)
        }
      }
      return null
    }

  /**
   * Get thread local cluster read MAC. Initialize the MAC with the [clusterReadMacKey].
   * @return thread local cluster read MAC, or `null`, if not available.
   */
  val threadLocalClusterReadMac: Mac?
    get() {
      if (clusterReadMacKey != null) {
        try {
          val mac = session.cipherSuite.threadLocalPseudoRandomFunctionMac
          mac?.init(clusterReadMacKey)
          return mac
        } catch (e: InvalidKeyException) {
          LOGGER.info("cluster read MAC error", e)
        }
      }
      return null
    }

  /**
   * Set client- and server-random.
   *
   * Only applied, if [DTLS_SUPPORT_KEY_MATERIAL_EXPORT] is enabled.
   * @param clientRandom client random
   * @param serverRandom server random
   */
  fun setRandoms(
    clientRandom: Random?,
    serverRandom: Random?,
  ) {
    if (supportExport) {
      this.clientRandom = clientRandom
      this.serverRandom = serverRandom
    }
  }

  /**
   * Calculate the pseudo random function for exporter as defined in
   * [RFC 5246](https://tools.ietf.org/html/rfc5246#section-5) and
   * [RFC 5705](https://tools.ietf.org/html/rfc5705#section-4).
   *
   * In order to use this function, [DTLS_SUPPORT_KEY_MATERIAL_EXPORT] must be enabled.
   *
   * @param label label to use.
   * @param context context, or `null`, if no context is used.
   * @param length length of the key.
   * @return calculated pseudo random for exporter
   * @throws IllegalArgumentException if label is not allowed for exporter
   * @throws IllegalStateException if `DTLS_SUPPORT_KEY_MATERIAL_EXPORT` is not
   * enabled or the random is missing.
   */
  fun exportKeyMaterial(
    label: ByteArray,
    context: ByteArray?,
    length: Int,
  ): ByteArray {
    check(supportExport) { "DTLS_SUPPORT_KEY_MATERIAL_EXPORT not enabled!" }
    if (clientRandom == null || serverRandom == null) {
      throw IllegalStateException("Random missing!")
    }
    val clientRandom0 = clientRandom
    val serverRandom0 = serverRandom
    requireNotNull(clientRandom0)
    requireNotNull(serverRandom0)
    var seed = Bytes.concatenate(clientRandom0, serverRandom0)
    if (context != null) {
      val writer = DatagramWriter(seed.size + context.size + 2)
      writer.writeBytes(seed)
      writer.write(context.size, Short.SIZE_BITS)
      writer.writeBytes(context)
      seed = writer.toByteArray()
    }
    return session.exportKeyMaterial(label, seed, length)
  }

  /**
   * Creates a new DTLS context initialized with a given record sequence number.
   * @param initialRecordSequenceNo the initial record sequence number to start from in epoch 0.
   * When starting a new handshake with a client that has successfully exchanged a cookie with the server,
   * the sequence number to use in the _SERVER_HELLO_ record _MUST_ be the same as the one from the successfully
   * validate _CLIENT_HELLO_ record (see [section 4.2.1 of RFC 6347 (DTLS 1.2)](https://tools.ietf.org/html/rfc6347#section-4.2.1) for details)
   * @param supportExport `true`, if [DTLS_SUPPORT_KEY_MATERIAL_EXPORT] is enabled.
   * @throws IllegalArgumentException if sequence number is out of the valid range `0...2^48`
   */
  constructor(initialRecordSequenceNo: Long, supportExport: Boolean) {
    require(initialRecordSequenceNo in 0..Record.MAX_SEQUENCE_NO) {
      "Initial sequence number must be greater than 0 and less than 2^48"
    }
    this.session = DTLSSession()
    this.handshakeTime = System.currentTimeMillis()
    this.sequenceNumbers[0] = initialRecordSequenceNo
    this.supportExport = supportExport
  }

  /**
   * Create instance from reader.
   * @param version version of serialized data.
   * @param reader reader with DTLS context state.
   * @throws IllegalArgumentException if the data is erroneous
   */
  private constructor(version: Int, reader: DatagramReader) {
    handshakeTime = reader.readLong(Long.SIZE_BITS)
    session = DTLSSession.fromReader(reader) ?: throw IllegalArgumentException("read session must not be null!")
    readEpoch = reader.read(Byte.SIZE_BITS)
    if (readEpoch > 0) {
      readState = DTLSConnectionState.fromReader(session.cipherSuite, session.compressionMethod, reader)
    }
    writeEpoch = reader.read(Byte.SIZE_BITS)
    if (writeEpoch == 1) {
      writeState = DTLSConnectionState.fromReader(session.cipherSuite, session.compressionMethod, reader)
    } else {
      require(writeEpoch <= 1) { "write epoch must be 1!" }
    }

    var data = reader.readVarBytes(Byte.SIZE_BITS)
    if (data != null) {
      writeConnectionId = ConnectionId(data)
    }
    readSequenceNumbers(reader)
    when (version) {
      VERSION_DEPRECATED -> {
        useDeprecatedCid = true
        effectiveMaxMessageSize = 0
        supportExport = false
      }

      VERSION_DEPRECATED_2 -> {
        useDeprecatedCid = reader.readNextByte() == 1.toByte()
        effectiveMaxMessageSize = reader.read(Short.SIZE_BITS)
        supportExport = false
      }

      VERSION -> {
        useDeprecatedCid = reader.readNextByte() == 1.toByte()
        effectiveMaxMessageSize = reader.read(Short.SIZE_BITS)
        supportExport = reader.readNextByte() == 1.toByte()
        if (supportExport) {
          data = reader.readVarBytes(Byte.SIZE_BITS)
          if (data != null) {
            clientRandom = Random(data)
          }
          data = reader.readVarBytes(Byte.SIZE_BITS)
          if (data != null) {
            serverRandom = Random(data)
          }
        }
      }

      else -> {
        supportExport = false
      }
    }
    reader.assertFinished("dtls-context")
  }

  /**
   * Write DTLS context state. Only writes state, if not already marked as closed.
   *
   * **Note**: the stream will contain not encrypted critical credentials. It is required to protect this data before exporting it.
   * @param writer writer for DTLS context state
   * @return `true`, if connection was written, `false`, otherwise, fi the dtls context is marked as closed.
   *
   */
  fun writeTo(writer: DatagramWriter): Boolean {
    if (markedAsClosed) {
      return false
    }
    val position = SerializationUtil.writeStartItem(writer, VERSION, Short.SIZE_BITS)
    writer.writeLong(handshakeTime, Long.SIZE_BITS)
    session.writeTo(writer)
    writer.write(readEpoch, Byte.SIZE_BITS)
    if (readEpoch > 0) {
      readState.writeTo(writer)
    }
    writer.write(writeEpoch, Byte.SIZE_BITS)
    if (writeEpoch > 0) {
      writeState.writeTo(writer)
    }
    writer.writeVarBytes(writeConnectionId, Byte.SIZE_BITS)
    writeSequenceNumbers(writer)
    // after deprecation
    writer.writeByte(if (useDeprecatedCid) 1.toByte() else 0.toByte())
    writer.write(effectiveMaxMessageSize, Short.SIZE_BITS)
    // after deprecation_2
    writer.writeByte(if (supportExport) 1.toByte() else 0.toByte())
    if (supportExport) {
      writer.writeVarBytes(clientRandom, Byte.SIZE_BITS)
      writer.writeVarBytes(serverRandom, Byte.SIZE_BITS)
    }
    SerializationUtil.writeFinishedItem(writer, position, Short.SIZE_BITS)
    return true
  }

  // For security issue, must be destroyed once it's not used or close_notify!
  override fun destroy() {
    SecretUtil.destroy(session)
    SecretUtil.destroy(clusterWriteMacKey)
    clusterWriteMacKey = null
    SecretUtil.destroy(clusterReadMacKey)
    clusterReadMacKey = null
    if (readState != DTLSConnectionState.NULL) {
      readState.destroy()
      readState = DTLSConnectionState.NULL
    }
    if (writeState != DTLSConnectionState.NULL) {
      writeState.destroy()
      writeState = DTLSConnectionState.NULL
    }
  }

  override fun isDestroyed(): Boolean {
    return SecretUtil.isDestroyed(session) && SecretUtil.isDestroyed(readState) &&
      SecretUtil.isDestroyed(writeState) && SecretUtil.isDestroyed(clusterReadMacKey) &&
      SecretUtil.isDestroyed(clusterWriteMacKey)
  }

  /**
   * Write the sequence-number state of this DTLS context.
   * @param writer writer for DTLS context state
   */
  fun writeSequenceNumbers(writer: DatagramWriter) {
    val position = SerializationUtil.writeStartItem(writer, SEQN_VERSION, Byte.SIZE_BITS)
    writer.writeLong(sequenceNumbers[writeEpoch], 48)
    writer.writeLong(receiveWindowLowerBoundary, 48)
    writer.writeLong(receivedRecordsVector, 64)
    writer.writeLong(macErrors, 64)
    SerializationUtil.writeFinishedItem(writer, position, Byte.SIZE_BITS)
  }

  /**
   * Read the sequence-number state for this DTLS context.
   * @param reader reader with sequence-number state for DTLS context state
   * @throws IllegalArgumentException if the data is erroneous
   */
  fun readSequenceNumbers(reader: DatagramReader) {
    val length = SerializationUtil.readStartItem(reader, SEQN_VERSION, Byte.SIZE_BITS)
    if (0 < length) {
      val rangeReader = reader.createRangeReader(length)
      val sequenceNumber = rangeReader.readLong(48)
      val receiveLowerBoundary = rangeReader.readLong(48)
      val receivedVector = rangeReader.readLong(64)
      val errors = rangeReader.readLong(64)
      rangeReader.assertFinished("dtls-context-sequence-numbers")

      val zeros = java.lang.Long.numberOfLeadingZeros(receivedVector)
      sequenceNumbers[writeEpoch] = sequenceNumber
      receiveWindowLowerBoundary = receiveLowerBoundary
      receivedRecordsVector = receivedVector
      receiveWindowUpperCurrent = receiveLowerBoundary + Long.SIZE_BITS - zeros - 1
      macErrors = errors
    }
  }

  override fun hashCode(): Int {
    val prime = 31
    var result = 1
    result = prime * result + (handshakeTime xor (handshakeTime ushr 32)).toInt()
    if (markedAsClosed) {
      result = prime * result + readEpochClosed
      result = prime * result + readSequenceNumberClosed.toInt()
    } else {
      result = prime * result + readEpoch
      result = prime * result + receiveWindowUpperCurrent.toInt()
    }
    result = prime * result + writeEpoch
    result = prime * result + sequenceNumbers[writeEpoch].toInt()
    result = prime * result + receiveWindowLowerBoundary.toInt()
    result = prime * result + (receivedRecordsVector xor (receivedRecordsVector ushr 32)).toInt()
    result = prime * result + (readConnectionId?.hashCode() ?: 0)
    result = prime * result + (writeConnectionId?.hashCode() ?: 0)
    result = prime * result + (if (useDeprecatedCid) 1 else 0)
    result = prime * result + session.hashCode()
    return result
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) {
      return true
    } else if (other == null) {
      return false
    } else if (other !is DTLSContext) {
      return false
    }
    if (session != other.session) {
      return false
    }
    if (handshakeTime != other.handshakeTime) {
      return false
    }
    if (markedAsClosed != other.markedAsClosed) {
      return false
    }
    if (markedAsClosed) {
      if (readEpochClosed != other.readEpochClosed) {
        return false
      }
      if (readSequenceNumberClosed != other.readSequenceNumberClosed) {
        return false
      }
    }
    if (!Bytes.equals(readConnectionId, other.readConnectionId)) {
      return false
    }
    if (!Bytes.equals(writeConnectionId, other.writeConnectionId)) {
      return false
    }
    if (readEpoch != other.readEpoch) {
      return false
    }
    if (receiveWindowLowerBoundary != other.receiveWindowLowerBoundary) {
      return false
    }
    if (receiveWindowUpperCurrent != other.receiveWindowUpperCurrent) {
      return false
    }
    if (receivedRecordsVector != other.receivedRecordsVector) {
      return false
    }
    if (writeEpoch != other.writeEpoch) {
      return false
    }
    if (sequenceNumbers[writeEpoch] != other.sequenceNumbers[writeEpoch]) {
      return false
    }
    if (useDeprecatedCid != other.useDeprecatedCid) {
      return false
    }
    if (effectiveMaxMessageSize != other.effectiveMaxMessageSize) {
      return false
    }
    return true
  }
}
