/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.fsm

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.annotation.JsonCreator
import io.kaxis.dtls.ConnectionIdGenerator
import io.kaxis.dtls.DTLSMessage
import io.kaxis.dtls.DefaultConnectionIdGenerator
import io.kaxis.dtls.Record
import io.kaxis.dtls.message.AlertMessage
import io.kaxis.dtls.message.ApplicationMessage
import io.kaxis.dtls.message.ChangeCipherSpecMessage
import io.kaxis.dtls.message.handshake.ClientHello
import io.kaxis.dtls.message.handshake.ClientKeyExchange
import io.kaxis.dtls.message.handshake.Finished
import io.kaxis.util.ClockUtil
import io.kaxis.util.DatagramReader
import org.apache.pekko.actor.typed.ActorRef
import org.apache.pekko.io.Udp
import java.net.InetSocketAddress

interface Command : FSMSerializable

enum class Idle : Command {
  INSTANCE,
}

enum class Stopped : Command {
  INSTANCE,
}

/**
 * The datagram packet message form sharding entity ID.
 */
@JsonAutoDetect
data class RawMessage
  @JsonCreator
  constructor(
    val raw: ByteArray,
    val peerAddress: InetSocketAddress,
    val socket: ActorRef<Udp.Send>,
  ) : Command {
    override fun equals(other: Any?): Boolean {
      if (this === other) return true
      if (other !is RawMessage) return false
      return raw.contentEquals(other.raw)
    }

    override fun hashCode(): Int {
      val prime = 31
      var result = 1
      result = prime * result + raw.contentHashCode()
      result = prime * result + peerAddress.address.address.contentHashCode()
      return result
    }

    /**
     * Convert to Records of [Record].
     */
    fun toRecords(idGenerator: ConnectionIdGenerator?): List<Record> {
      val timestamp = ClockUtil.nanoRealtime()
      val reader = DatagramReader(raw)
      return Record.fromReader(reader, idGenerator, timestamp).map { record ->
        record.peerAddress = peerAddress
        record
      }
    }

    /**
     * Check, if is a plaintext.
     */
    val isPlainText: Boolean
      get() {
        val timestamp = ClockUtil.nanoRealtime()
        val reader = DatagramReader(raw)
        val records = Record.fromReader(reader, DefaultConnectionIdGenerator(6), timestamp)
        return records.isEmpty()
      }
  }

/**
 * Constructor of a decrypted message which received from a client.
 * @param decrypt datagram packet.
 * @param socket udp client [ActorRef].
 */
@JsonAutoDetect
data class DecryptMessage(
  val decrypt: ByteArray,
  val peerAddress: InetSocketAddress,
  val socket: ActorRef<Udp.Send>,
) : Command {
  /**
   * Check, if is a plaintext.
   */
  val isPlainText: Boolean
    get() {
      val timestamp = ClockUtil.nanoRealtime()
      val reader = DatagramReader(decrypt)
      val records = Record.fromReader(reader, DefaultConnectionIdGenerator(6), timestamp)
      return records.isEmpty()
    }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is DecryptMessage) return false
    return decrypt.contentEquals(other.decrypt)
  }

  override fun hashCode(): Int {
    val prime = 31
    var result = 1
    result = prime * result + decrypt.contentHashCode()
    result = prime * result + peerAddress.address.address.contentHashCode()
    return result
  }
}

// mbedTLS DTLS server state machine.

interface Recipient<T : DTLSMessage> : Command {
  /** DTLS record's properties will */
  val decodedRecord: Record
  val message: T
  val peerAddress: InetSocketAddress
  val socket: ActorRef<Udp.Send>
}

class ClientHelloRequest(
  override val decodedRecord: Record,
  override val message: ClientHello,
  override val peerAddress: InetSocketAddress,
  override val socket: ActorRef<Udp.Send>,
) : Recipient<ClientHello>

class ClientKeyExchangeRequest<T : ClientKeyExchange>(
  override val decodedRecord: Record,
  override val message: T,
  override val peerAddress: InetSocketAddress,
  override val socket: ActorRef<Udp.Send>,
) : Recipient<T>

class FinishedRequest(
  override val decodedRecord: Record,
  override val message: Finished,
  override val peerAddress: InetSocketAddress,
  override val socket: ActorRef<Udp.Send>,
) : Recipient<Finished>

class ApplicationDataRequest(
  override val decodedRecord: Record,
  override val message: ApplicationMessage,
  override val peerAddress: InetSocketAddress,
  override val socket: ActorRef<Udp.Send>,
) : Recipient<ApplicationMessage>

class AlertWarningCloseNotifyRequest(
  override val decodedRecord: Record,
  override val message: AlertMessage,
  override val peerAddress: InetSocketAddress,
  override val socket: ActorRef<Udp.Send>,
) : Recipient<AlertMessage>

class ChangeCipherSpecMessageRequest(
  override val decodedRecord: Record,
  override val message: ChangeCipherSpecMessage,
  override val peerAddress: InetSocketAddress,
  override val socket: ActorRef<Udp.Send>,
) : Recipient<ChangeCipherSpecMessage>
