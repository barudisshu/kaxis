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

import io.kaxis.dtls.message.AlertMessage
import io.kaxis.dtls.message.ApplicationMessage
import io.kaxis.dtls.message.ChangeCipherSpecMessage
import io.kaxis.dtls.message.HandshakeMessage
import io.kaxis.exception.HandshakeException
import io.kaxis.exception.InvalidMacException
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.net.InetSocketAddress
import java.security.GeneralSecurityException

/**
 * Record
 *
 * @constructor Create empty Record
 */
class Record {
  companion object {
    private val LOGGER: Logger = LoggerFactory.getLogger(Record::class.java)

    const val CONTENT_TYPE_BITS = 8

    const val VERSION_BITS = 8 // for major and minor each

    const val EPOCH_BITS = 16

    const val SEQUENCE_NUMBER_BITS = 48

    const val LENGTH_BITS = 16

    const val CID_LENGTH_BITS = 8

    const val RECORD_HEADER_BITS =
      CONTENT_TYPE_BITS + VERSION_BITS + VERSION_BITS + EPOCH_BITS + SEQUENCE_NUMBER_BITS + LENGTH_BITS

    /**
     * Bytes for dtls record header.
     */
    const val RECORD_HEADER_BYTES = RECORD_HEADER_BITS / Byte.SIZE_BITS

    /**
     * The payload length of all headers of a DTLS handshake message payload.
     * - 12 bytes DTLS handshake message header
     * - 13 bytes DTLS record header
     *
     * 25 bytes in total.
     */
    const val DTLS_HANDSHAKE_HEADER_LENGTH = RECORD_HEADER_BYTES + HandshakeMessage.MESSAGE_HEADER_LENGTH_BYTES

    /**
     * The maximum plaintext fragment size for TLS 1.2
     */
    const val DTLS_MAX_PLAINTEXT_FRAGMENT_LENGTH = 16384 // 2^14

    const val MAX_SEQUENCE_NO = 281474976710655L // 2^48 - 1

    /**
     * Sequence number placeholder for CID records.
     */
    private val SEQUENCE_NUMBER_PLACEHOLDER = byteArrayOf(-1, -1, -1, -1, -1, -1, -1, -1)

    /**
     * Parses a sequence of _DTLSCiphertext_ structures into Record instances.
     *
     * The binary representation is expected to comply with the _DTLSCiphertext_ structure defined in [RFC 6347, Section 4.3.1](https://tools.ietf.org/html/rfc6347#section-4.3.1).
     *
     * @param reader a reader with the raw binary representation containing one or more DTLSCiphertext structures
     * @param cidGenerator the connection id generator. May be `null`.
     * @param receiveNanos uptime nanoseconds of receiving this record
     * @return the Record instances
     * @throws NullPointerException if either one of the reader or peer address is `null`
     */
    @JvmStatic
    @Suppress("kotlin:S3776")
    fun fromReader(
      reader: DatagramReader?,
      cidGenerator: ConnectionIdGenerator?,
      receiveNanos: Long,
    ): MutableList<Record> {
      requireNotNull(reader) { "Reader must not be null" }

      val datagramLength = reader.bitsLeft() / Byte.SIZE_BITS
      val records = mutableListOf<Record>()

      while (reader.bytesAvailable()) {
        if (reader.bitsLeft() < RECORD_HEADER_BITS) {
          LOGGER.debug("Received truncated DTLS record(s). Discarding ...")
          return records
        }

        val type = reader.read(CONTENT_TYPE_BITS)
        val major = reader.read(VERSION_BITS)
        val minor = reader.read(VERSION_BITS)
        val version = ProtocolVersion.valueOf(major, minor)

        val epoch = reader.read(EPOCH_BITS)
        val sequenceNumber = reader.readLong(SEQUENCE_NUMBER_BITS)

        var connectionId: ConnectionId? = null
        if (type == ContentType.TLS12_CID.code) {
          if (cidGenerator == null) {
            LOGGER.debug("Received TLS_CID record, but cid is no supported. Discarding ...")
            return records
          } else if (cidGenerator.useConnectionId()) {
            try {
              connectionId = cidGenerator.read(reader)
              if (connectionId == null) {
                LOGGER.debug("Received TLS_CID record, but cid is not matching. Discarding ...")
                return records
              }
            } catch (ex: RuntimeException) {
              LOGGER.debug("Received TLS_CID record, failed to read cid. Discarding ...", ex)
              return records
            }
          } else {
            LOGGER.debug("Received TLS_CID record, but cid is not used. Discarding ...")
            return records
          }
        }
        val length = reader.read(LENGTH_BITS)
        val left = reader.bitsLeft() / Byte.SIZE_BITS
        if (left < length) {
          LOGGER.debug(
            "Received truncated DTLS record(s) ({} bytes, but only {} available). {} records, {} bytes. Discarding ...",
            length,
            left,
            records.size,
            datagramLength,
          )
          return records
        }

        // delay decryption/interpretation of fragment
        val fragmentBytes = reader.readBytes(length)

        val contentType = ContentType.getTypeByValue(type)
        if (contentType == null) {
          LOGGER.debug("Received DTLS record of unsupported type [{}]. Discarding ...", type)
        } else {
          records.add(
            Record(
              contentType,
              version,
              epoch,
              sequenceNumber,
              connectionId,
              fragmentBytes,
              receiveNanos,
              records.isNotEmpty(),
            ),
          )
        }
      }

      return records
    }

    /**
     * Read the connection id.
     * @param reader reader with the raw received record.
     * @param cidGenerator cid generator.
     * @return connection, or `null`, if not available.
     * @throws NullPointerException if either reader or cid generator is `null`.
     * @throws IllegalArgumentException if the cid generator doesn't use cid or the record is too short.
     */
    @JvmStatic
    fun readConnectionIdFromReader(
      reader: DatagramReader?,
      cidGenerator: ConnectionIdGenerator?,
    ): ConnectionId? {
      requireNotNull(reader) { "Reader must not be null" }
      requireNotNull(cidGenerator) { "CID generator must not be null" }
      requireNotNull(cidGenerator.useConnectionId()) { "CID generator must use CID" }
      require(reader.bitsLeft() >= RECORD_HEADER_BITS) { "Record too small for DTLS header" }

      val type = reader.read(CONTENT_TYPE_BITS)
      if (type != ContentType.TLS12_CID.code) {
        return null
      }

      reader.skip((VERSION_BITS + VERSION_BITS + EPOCH_BITS).toLong() + SEQUENCE_NUMBER_BITS)
      val connectionId = cidGenerator.read(reader)
      val length = reader.read(LENGTH_BITS)
      val left = reader.bitsLeft() / Byte.SIZE_BITS
      require(left >= length) { "Record too small for DTLS length $length" }

      return connectionId
    }
  }

  /**
   * The higher-level protocol used to process the enclosed fragment
   */
  lateinit var type: ContentType

  /**
   * The version of the protocol being employed. DTLS version 1.2 uses {254, 253}
   */
  var version: ProtocolVersion = ProtocolVersion.VERSION_DTLS_1_2

  /**
   * A counter value that is incremented on every cipher state change
   */
  var epoch: Int = 0

  /**
   * The sequence number for this record
   */
  var sequenceNumber: Long = 0

  /**
   * Receive time in uptime nanoseconds. [ClockUtil.nanoRealtime]
   */
  var receiveNanos: Long = 0

  /**
   * Record follow other record in datagram. Used to analyze construction of handshake.
   */
  var followUpRecord: Boolean = false

  /**
   * The application data. This data is transparent and treated as an independent block to be dealt with by the higher-level
   * protocol specified by the type field.
   */
  var fragment: DTLSMessage? = null

  /**
   * The raw byte representation of the fragment.
   */
  var fragmentBytes: ByteArray? = null

  /**
   * The connection id.
   */
  var connectionId: ConnectionId? = null

  /**
   * Use deprecated MAC calculation.
   */
  var useDeprecatedMac: Boolean = false

  /**
   * Padding to be used with cid
   */
  var padding: Int = 0

  /**
   * The peer address.
   */
  var peerAddress: InetSocketAddress? = null

  /**
   * check, if new tls_cid record must be used.
   *
   * See [Draft dtls-connection-id](https://datatracker.ietf.org/doc/draft-ietf-tls-dtls-connection-id/) 2019-feb-18: the last discussion agreement
   * is NOT to use an empty CID for tls_cid records.
   */
  @get:JvmName("useConnectionId")
  val useConnectionId: Boolean
    get() {
      val cid = connectionId
      return cid != null && cid.isNotEmpty()
    }

  /**
   * Check, if record is decoded.
   * @return `true`, if records is decode, `false`, otherwise.
   */
  val isDecoded: Boolean
    get() = fragment != null

  /**
   * Check, if record is **CLIENT_HELLO** of epoch 0. This is important to detect a new association according
   * RFC 6347, section 4.2.8.
   * @return `true`, if record contains **CLIENT_HELLO** of epoch 0, `false` otherwise.
   */
  val isNewClientHello: Boolean
    get() {
      if (0 < epoch || type != ContentType.HANDSHAKE || fragmentBytes?.size == 0) {
        return false
      }
      val handshakeType = HandshakeType.getTypeByCode(fragmentBytes!![0].toInt())
      return handshakeType == HandshakeType.CLIENT_HELLO
    }

  /**
   * Gets the length of the fragment contained in this record in bytes.
   *
   * The overall length of this record's _DTLSCiphertext_ representation is thus `Record.length + 13(DTLS record headers) + CID` bytes.
   * @return the fragment length excluding record headers
   */
  val fragmentLength: Int
    get() = fragmentBytes?.size ?: 0

  val size: Int
    get() {
      val cid = if (useConnectionId) connectionId?.length() ?: 0 else 0
      return RECORD_HEADER_BYTES + cid + fragmentLength
    }

  /**
   * Creates a record from a _DTLSCiphertext_ struct received from the network. Called when reconstructing the
   * record from a byte array. The fragment will remain in its binary representation up to the DTLS Layer.
   * @param type the content type. The new record type [ContentType.TLS12_CID] is directly supported.
   * @param version the version
   * @param epoch the epoch
   * @param sequenceNumber the sequence number
   * @param connectionId the connection id
   * @param fragmentBytes the encrypted data
   * @param receiveNanos uptime nanoseconds of receiving this record
   * @param followUpRecord record follows up another record in the same datagram
   * @throws IllegalArgumentException if the given sequence number is longer than 48 bits or is less than 0. Or the given epoch is less than 0.
   * @throws NullPointerException if the given type, protocol version, or fragment bytes is `null`.
   */
  constructor(
    type: ContentType?,
    version: ProtocolVersion,
    epoch: Int,
    sequenceNumber: Long,
    connectionId: ConnectionId?,
    fragmentBytes: ByteArray?,
    receiveNanos: Long,
    followUpRecord: Boolean,
  ) : this(version, epoch, sequenceNumber, receiveNanos, followUpRecord) {
    requireNotNull(type) { "Type must not be null" }
    requireNotNull(fragmentBytes) { "Fragment bytes must not be null" }
    this.type = type
    this.connectionId = connectionId
    this.fragmentBytes = fragmentBytes
  }

  /**
   * Creates an outbound record containing a [DTLSMessage] as its payload. The given _fragment_ is encoded into
   * its binary representation and encrypted according to the given session's current write state. In order to
   * create a `Record` containing an un-encrypted fragment, use the [Record] constructor.
   *
   * @param type the type of the record's payload. The new record type [ContentType.TLS12_CID] is not supported directly.
   * Provide the inner type and `true` for the parameter cid
   * @param epoch the epoch
   * @param fragment the payload
   * @param context the dtls-context to determine the current write state from
   * @param cid if `true` use write connection id from provided session. Otherwise use `null` as connection id
   * @param pad if cid is enabled, pad could be used to add that number of zero-bytes as padding to the payload
   * to obfuscate the payload length.
   *
   * @throws IllegalStateException if the context sequence number is longer than 48 bits.
   * @throws IllegalArgumentException if the context sequence number is less than0, the given epoch is less than 0,
   * the provided type is not supported or the fragment could not be converted into bytes. Or the provided session
   * doesn't haven a peer address.
   * @throws NullPointerException if the given type, fragment or session is `null`.
   * @throws GeneralSecurityException if the message could not be encrypted, e.g. because the JVM does not support the
   * negotiated cipher suite's cipher algorithm.
   */
  constructor(
    type: ContentType?,
    epoch: Int,
    fragment: DTLSMessage?,
    context: DTLSContext?,
    cid: Boolean,
    pad: Int,
  ) : this(
    ProtocolVersion.VERSION_DTLS_1_2,
    epoch,
    if ((context == null || epoch < 0)) 0 else context.getNextSequenceNumber(epoch),
    0,
    false,
  ) {
    requireNotNull(fragment) { "Fragment must not be null" }
    requireNotNull(context) { "Context must not be null" }
    when (type) {
      ContentType.ALERT,
      ContentType.APPLICATION_DATA,
      ContentType.HANDSHAKE,
      ContentType.CHANGE_CIPHER_SPEC,
      -> this.type = type

      else -> throw IllegalArgumentException("Not supported content type: $type")
    }
    if (cid) {
      this.connectionId = context.writeConnectionId
      // deprecated CID comes with the deprecated MAC calculation
      this.useDeprecatedMac = context.useDeprecatedCid
      this.padding = pad
    }
    setEncodedFragment(context.getWriteState(epoch), fragment)
  }

  /**
   * Sets the DTLS fragment. At the same time, it creates the corresponding raw binary representation and
   * encrypts it if necessary (depending on current connection state). If cid is used, create also the "inner plain
   * text" containing the payload, the original record type, and optional padding with zeros before encryption.
   *
   * @param outgoingWriteState write state to be applied to fragment
   * @param fragment the DTLS fragment
   *
   * @throws GeneralSecurityException if the message could not be encrypted, e.g. because the JVM does not support
   * the negotiated cipher suite's cipher algorithm.
   * @throws NullPointerException if [DTLSMessage.toByteArray] return `null`.
   */
  @Throws(GeneralSecurityException::class)
  private fun setEncodedFragment(
    outgoingWriteState: DTLSConnectionState,
    fragment: DTLSMessage,
  ) {
    // serialize fragment and if necessary encrypt byte array
    var byteArray = fragment.toByteArray()
    requireNotNull(byteArray) { "fragment must not return null" }
    if (useConnectionId) {
      val index = byteArray.size
      byteArray = byteArray.copyOf(index + 1 + padding)
      byteArray[index] = type.code.toByte()
    }
    this.fragmentBytes = outgoingWriteState.encrypt(this, byteArray)
    this.fragment = fragment
    require(this.fragmentBytes != null) { "Fragment missing encoded bytes!" }
  }

  /**
   * Creates an outbound record representing a [DTLSMessage] as its payload. The payload will be sent unencrypted using epoch 0.
   * @param type the type of the record's payload. The new record type [ContentType.TLS12_CID] is not supported.
   * @param version the version
   * @param sequenceNumber the 48-bit sequence number
   * @param fragment the payload to send
   * @throws IllegalArgumentException if the given sequence number is longer than 48 bits or is less than 0, the given
   * epoch is less than 0, or the fragment could not be converted into bytes.
   * @throws NullPointerException if the given type, or fragment is `null`.
   */
  constructor(type: ContentType?, version: ProtocolVersion?, sequenceNumber: Long, fragment: DTLSMessage?) :
    this(version, 0, sequenceNumber, 0, false) {
    requireNotNull(type) { "Type must not be null" }
    requireNotNull(fragment) { "Fragment must not be null" }
    when (type) {
      ContentType.ALERT,
      ContentType.APPLICATION_DATA,
      ContentType.HANDSHAKE,
      ContentType.CHANGE_CIPHER_SPEC,
      -> this.type = type

      else -> throw IllegalArgumentException("Not supported content type: $type")
    }
    this.fragment = fragment
    this.fragmentBytes = fragment.toByteArray()

    require(this.fragmentBytes != null) { "Fragment missing encoded bytes!" }
  }

  private constructor(
    version: ProtocolVersion?,
    epoch: Int,
    sequenceNumber: Long,
    receiveNanos: Long,
    followUpRecord: Boolean,
  ) {
    require(sequenceNumber <= MAX_SEQUENCE_NO) { "Sequence number must be 48 bits only! $sequenceNumber" }
    require(sequenceNumber >= 0) { "Sequence number must not be less than 0! $sequenceNumber" }
    require(epoch >= 0) { "Epoch must not be less than 0! $epoch" }
    requireNotNull(version) { "Version must not be null" }
    this.version = version
    this.epoch = epoch
    this.sequenceNumber = sequenceNumber
    this.receiveNanos = receiveNanos
    this.followUpRecord = followUpRecord
  }

  /**
   * Generates the explicit part of the nonce to be used with AEAD Cipher. [RFC 6655, Section 3](https://tools.ietf.org/html/rfc6655#section-3)
   * encourages the use of the session's 16bit epoch value concatenated with a monotonically increasing 48bit
   * sequence number as the explicit nonce.
   * @param writer writer for nonce
   */
  fun writeExplicitNonce(writer: DatagramWriter) {
    writer.write(epoch, EPOCH_BITS)
    writer.writeLong(sequenceNumber, SEQUENCE_NUMBER_BITS)
  }

  /**
   * Generates the additional authentication data. According [useConnectionId] and [useDeprecatedMac], use
   * [generateAdditionalDataRfc6347], [generateAdditionalDataCidDeprecated], or [generateAdditionalDataCid]
   * @param length length of the data to be authenticated
   * @return the additional authentication data.
   */
  fun generateAdditionalData(length: Int): ByteArray {
    return if (!useConnectionId) {
      generateAdditionalDataRfc6347(length)
    } else if (useDeprecatedMac) {
      generateAdditionalDataCidDeprecated(length)
    } else {
      generateAdditionalDataCid(length)
    }
  }

  /**
   * See [RFC 5246](https://tools.ietf.org/html/rfc5246#section-6.2.3.3) and [RFC 6347](https://tools.ietf.org/html/rfc6347#section-4.1.2.1):
   * ```
   *  additional_data = seq_num
   *                  + TLSCompressed.type
   *                  + TLSCompressed.version
   *                  + TLSCompressed.length;
   * ```
   * Where "+" denotes concatenation.
   * @param length length of the data to be authenticated
   * @return the additional authentication data.
   */
  fun generateAdditionalDataRfc6347(length: Int): ByteArray {
    val writer = DatagramWriter(RECORD_HEADER_BYTES)

    writer.write(epoch, EPOCH_BITS)
    writer.writeLong(sequenceNumber, SEQUENCE_NUMBER_BITS)

    writer.write(type.code, CONTENT_TYPE_BITS)
    writer.write(version.major, VERSION_BITS)
    writer.write(version.minor, VERSION_BITS)
    writer.write(length, LENGTH_BITS)

    return writer.toByteArray()
  }

  /**
   * Generates the additional authentication data according [draft dtls connection id (up to Version 8), 5. Record Payload Protection](https://datatracker.ietf.org/doc/html/draft-ietf-tls-dtls-connection-id-08#section-5):
   *
   * ```
   *  additional_data = epoch
   *                  + seq_num
   *                  + tls_cid
   *                  + TLSCompressed.version
   *                  + connection_id
   *                  + connection_id_length
   *                  + TLSCompressed.length;
   * ```
   * Where "+" denotes concatenation and the connection_id_length is encoded in one unit8 byte.
   * @param length length of the data to be authenticated
   * @return the additional authentication data.
   */
  fun generateAdditionalDataCidDeprecated(length: Int): ByteArray {
    val cid = connectionId
    requireNotNull(cid) { "Deprecated Cid must not be null!" }

    val writer = DatagramWriter(RECORD_HEADER_BYTES + cid.length() + 1)

    writer.write(epoch, EPOCH_BITS)
    writer.writeLong(sequenceNumber, SEQUENCE_NUMBER_BITS)

    writer.write(ContentType.TLS12_CID.code, CONTENT_TYPE_BITS)
    writer.write(version.major, VERSION_BITS)
    writer.write(version.minor, VERSION_BITS)
    writer.writeBytes(cid.byteArray)
    writer.write(cid.length(), CID_LENGTH_BITS)
    writer.write(length, LENGTH_BITS)

    return writer.toByteArray()
  }

  /**
   * Generates the additional authentication data according [RFC 9146, Connection Identifier for DTLS 1.2, 5. Record Payload Protection](https://www.rfc-editor.org/rfc/rfc9146.html#section-5):
   * ```
   *  additional_data = seq_num_placeholder
   *                  + tls_cid
   *                  + connection_id_length
   *                  + tls_cid
   *                  + TLSCompressed.version
   *                  + epoch
   *                  + sequence_number
   *                  + connection_id
   *                  + TLSCompressed.length;
   * ```
   * Where "+" denotes concatenation and the connection_id_length is encoded in one uint8 byte.
   * @param length length of the data to be authenticated
   * @return the additional authentication data.
   */
  fun generateAdditionalDataCid(length: Int): ByteArray {
    val cid = connectionId
    requireNotNull(cid) { "Cid must not be null!" }

    val writer = DatagramWriter(RECORD_HEADER_BYTES + cid.length() + 1 + 1 + 8)

    writer.writeBytes(SEQUENCE_NUMBER_PLACEHOLDER)
    writer.write(ContentType.TLS12_CID.code, CONTENT_TYPE_BITS)
    writer.write(cid.length(), CID_LENGTH_BITS)
    writer.write(ContentType.TLS12_CID.code, CONTENT_TYPE_BITS)
    writer.write(version.major, VERSION_BITS)
    writer.write(version.minor, VERSION_BITS)
    writer.write(epoch, EPOCH_BITS)
    writer.writeLong(sequenceNumber, SEQUENCE_NUMBER_BITS)
    writer.writeBytes(cid.byteArray)
    writer.write(length, LENGTH_BITS)

    return writer.toByteArray()
  }

  /**
   * Encodes this record into its corresponding _DTLSCiphertext_ structure.
   * @return a byte array containing the _DTLSCiphertext_ structure
   */
  fun toByteArray(): ByteArray {
    val useCid = useConnectionId
    var length = fragmentLength + RECORD_HEADER_BYTES
    if (useCid) {
      length += connectionId?.length() ?: 0
    }
    val writer = DatagramWriter(length)

    if (useCid) {
      writer.write(ContentType.TLS12_CID.code, CONTENT_TYPE_BITS)
    } else {
      writer.write(type.code, CONTENT_TYPE_BITS)
    }

    writer.write(version.major, VERSION_BITS)
    writer.write(version.minor, VERSION_BITS)

    writer.write(epoch, EPOCH_BITS)
    writer.writeLong(sequenceNumber, SEQUENCE_NUMBER_BITS)
    if (useCid) {
      writer.writeBytes(connectionId?.byteArray)
    }
    writer.write(fragmentLength, LENGTH_BITS)
    writer.writeBytes(fragmentBytes)

    return writer.toByteArray()
  }

  /**
   * Decode the object representation of this record's _DTLSPlaintext.fragment_. If the record uses the new
   * record type [ContentType.TLS12_CID] the [type] is update with the type of the inner plaintext. If CID is used,
   * [useDeprecatedMac] must be called before decoding a fragment.
   * @param readState read state of the epoch for incoming messages.
   * @throws
   */
  @Throws(GeneralSecurityException::class, HandshakeException::class)
  fun decodeFragment(readState: DTLSConnectionState) {
    require(fragment == null) {
      LOGGER.error("DTLS read state already applied!")
      "DTLS read state already applied!"
    }

    var actualType: ContentType? = type
    // decide, which type of fragment need decryption
    var decryptedMessage =
      readState.decrypt(this, fragmentBytes) ?: throw InvalidMacException("Decrypt authentication message failed!")

    if (ContentType.TLS12_CID == type) {
      var index = decryptedMessage.size - 1
      while (index >= 0 && decryptedMessage[index] == 0.toByte()) {
        --index
      }
      if (index < 0) {
        throw GeneralSecurityException("no inner type!")
      }
      val typeCode = decryptedMessage[index]
      actualType = ContentType.getTypeByValue(typeCode.toInt())
      if (actualType == null) {
        throw GeneralSecurityException("unknown inner type! $typeCode")
      }
      decryptedMessage = decryptedMessage.copyOf(index)
    }

    when (actualType) {
      ContentType.ALERT -> fragment = AlertMessage.fromByteArray(decryptedMessage)
      ContentType.APPLICATION_DATA -> fragment = ApplicationMessage.fromByteArray(decryptedMessage)
      ContentType.CHANGE_CIPHER_SPEC -> fragment = ChangeCipherSpecMessage.fromByteArray(decryptedMessage)
      ContentType.HANDSHAKE -> fragment = HandshakeMessage.fromByteArray(decryptedMessage)
      ContentType.HEARTBEAT -> LOGGER.error("HEARTBEAT message is unsupported!!!")
      else -> LOGGER.debug("Cannot decrypt message of unsupported type [{}]", type)
    }
    type = actualType!!
  }

  override fun toString(): String {
    val sb = StringBuilder()
    sb.append("==[ DTLS Record ]===================================================").append(Utility.LINE_SEPARATOR)
    sb.append("Content Type: ").append(type).append(Utility.LINE_SEPARATOR)
    if (peerAddress != null) {
      sb.append("Peer address: ").append(peerAddress).append(Utility.LINE_SEPARATOR)
    }
    sb.append("Version: ").append(version.major).append(", ").append(version.minor).append(Utility.LINE_SEPARATOR)
    sb.append("Epoch: ").append(epoch).append(Utility.LINE_SEPARATOR)
    sb.append("Sequence Number: ").append(sequenceNumber).append(Utility.LINE_SEPARATOR)
    if (connectionId != null) {
      sb.append("connection id: ").append(connectionId!!.asString).append(Utility.LINE_SEPARATOR)
    }
    sb.append("Length: ").append(fragmentBytes?.size ?: 0).append(" bytes").append(Utility.LINE_SEPARATOR)
    sb.append("Fragment: ").append(Utility.LINE_SEPARATOR)
    if (fragment != null) {
      sb.append(fragment!!.toString(1))
    } else {
      sb.append("fragment is not decrypted yet").append(Utility.LINE_SEPARATOR)
    }
    sb.append("====================================================================").append(Utility.LINE_SEPARATOR)
    return sb.toString()
  }
}
