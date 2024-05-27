/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis

import io.kaxis.ansi.Highlight
import io.kaxis.dtls.ConnectionIdGenerator
import io.kaxis.dtls.DTLSConnectionState
import io.kaxis.dtls.Record
import io.kaxis.dtls.message.FragmentedHandshakeMessage
import io.kaxis.dtls.message.handshake.ClientHello
import io.kaxis.fsm.*
import io.kaxis.fsm.State.Stage.*
import io.kaxis.handler.impl.Stage0ReceivedClientHello
import io.kaxis.handler.impl.Stage1ReceivedClientHello
import io.kaxis.util.ClockUtil
import io.kaxis.util.Utility
import org.apache.pekko.actor.typed.ActorRef
import org.apache.pekko.actor.typed.ActorSystem
import org.apache.pekko.actor.typed.Behavior
import org.apache.pekko.actor.typed.SupervisorStrategy
import org.apache.pekko.actor.typed.javadsl.ActorContext
import org.apache.pekko.actor.typed.javadsl.Behaviors
import org.apache.pekko.cluster.sharding.typed.ShardingEnvelope
import org.apache.pekko.cluster.sharding.typed.javadsl.ClusterSharding
import org.apache.pekko.cluster.sharding.typed.javadsl.Entity
import org.apache.pekko.cluster.sharding.typed.javadsl.EntityTypeKey
import org.apache.pekko.io.Udp
import org.apache.pekko.persistence.typed.PersistenceId
import org.apache.pekko.persistence.typed.state.javadsl.CommandHandlerWithReply
import org.apache.pekko.persistence.typed.state.javadsl.DurableStateBehaviorWithEnforcedReplies
import org.apache.pekko.persistence.typed.state.javadsl.ReplyEffect
import org.apache.pekko.util.ByteString
import java.time.Duration
import java.util.concurrent.TimeUnit

/**
 * A DTLS record_layer which sharding its connection_id.
 *
 * @param shard [ClusterSharding]
 *
 * @author galudisu
 */
class RecordLayer private constructor(
  private val context: ActorContext<Command>,
  private val shard: ActorRef<ClusterSharding.ShardCommand>,
  persistenceId: PersistenceId,
) : DurableStateBehaviorWithEnforcedReplies<Command, State>(
    persistenceId,
    SupervisorStrategy.restartWithBackoff(Duration.ofSeconds(10), Duration.ofSeconds(30), 0.2),
  ) {
  companion object {
    private const val NAME = "RecordLayer"
    val TypeKey: EntityTypeKey<Command> = EntityTypeKey.create(Command::class.java, NAME)

    /**
     * Once an Actor system boostrap, invoke sharding.
     * @param system actor system.
     */
    @JvmStatic
    fun initSharding(system: ActorSystem<Unit>): ActorRef<ShardingEnvelope<Command>> =
      ClusterSharding.get(system).init(
        Entity
          .of(TypeKey) { ctx ->
            create(ctx.shard, PersistenceId.of(ctx.entityTypeKey.name(), ctx.entityId))
          }.withStopMessage(Stopped.INSTANCE),
      )

    /**
     * Create record layer behaviors.
     * @param shard cluster shard [ActorRef] info
     * @param persistenceId regard as connected client inet socket address or cid.
     * @return #typed#behavior
     */
    @JvmStatic
    fun create(
      shard: ActorRef<ClusterSharding.ShardCommand>,
      persistenceId: PersistenceId,
    ): Behavior<Command> {
      return Behaviors.setup { ctx ->
        ctx.setReceiveTimeout(Duration.ofSeconds(30), Idle.INSTANCE)
        return@setup RecordLayer(ctx, shard, persistenceId)
      }
    }
  }

  /**
   * This is the beginning state of the implementation.
   */
  override fun emptyState(): State {
    // the very fist state is Stage=0, FSM=Preparing.
    return State.empty()
  }

  /**
   * While defined with [DurableStateBehaviorWithEnforcedReplies] there will be compilation errors
   * if the returned effect isn't a [ReplyEffect], which can be created with `Effect().reply`, `Effect().noReply`,
   * `Effect().thenReply`, or `Effect().thenNoReply`.
   */
  override fun commandHandler(): CommandHandlerWithReply<Command, State> {
    val discard: (State, Command) -> ReplyEffect<State> = { state, command ->
      context.log.debug("Command: {} discard in stage: {}", command, state.stage)
      Effect().noReply()
    }

    fun discardTo(stage: State.Stage): (State, Command) -> ReplyEffect<State> =
      { state, command ->
        state.stage = stage
        context.log.debug("Command: {} discard but goto: {}", command, state.stage)
        Effect().persist(state).thenNoReply()
      }

    val builder = newCommandHandlerWithReplyBuilder()

    /*
     * This is the beginning state of the implementation.
     */
    builder
      .forState { it.stage == S0 }
      .onCommand(
        ClientHelloRequest::class.java,
      ) { state, cmd -> Stage0ReceivedClientHello(context, Effect()).apply(state, cmd) }
      .onCommand(ClientKeyExchangeRequest::class.java, discard)
      .onCommand(FinishedRequest::class.java, discard)
      .onCommand(ApplicationDataRequest::class.java, discard)
      .onCommand(AlertWarningCloseNotifyRequest::class.java, discard)
      .onCommand(ChangeCipherSpecMessageRequest::class.java, discardTo(S2))

    builder
      .forState { it.stage == S1 }
      .onCommand(
        ClientHelloRequest::class.java,
      ) { state, cmd -> Stage1ReceivedClientHello(context, Effect()).apply(state, cmd) }
      .onCommand(ClientKeyExchangeRequest::class.java, discard)
      .onCommand(FinishedRequest::class.java, discard)
      .onCommand(ApplicationDataRequest::class.java, discard)
      .onCommand(AlertWarningCloseNotifyRequest::class.java, discard)
      .onCommand(ChangeCipherSpecMessageRequest::class.java, discardTo(S2))

    // Dead in Stage 2!!!! the client must open a new connection for security protection!!!!
    builder
      .forState { it.stage == S2 }
      .onCommand(ClientHelloRequest::class.java, discard)
      .onCommand(ClientKeyExchangeRequest::class.java, discard)
      .onCommand(ChangeCipherSpecMessageRequest::class.java, discard)
      .onCommand(FinishedRequest::class.java, discard)
      .onCommand(ApplicationDataRequest::class.java, discard)
      .onCommand(AlertWarningCloseNotifyRequest::class.java, discard)

    builder
      .forState { it.stage == S3 }
      .onCommand(ClientKeyExchangeRequest::class.java) { state, cmd -> onStage3ReceivedClientKeyExchange(state, cmd) }
      // We are able to take a step back from S3 to S1.
      // Sending three CLIENT_HELLO messages is equal to sending one CLIENT_HELLO message.
      // This happens on retransmission
      .onCommand(ClientHelloRequest::class.java, discardTo(S1))
      .onCommand(ApplicationDataRequest::class.java, discardTo(S1))
      .onCommand(FinishedRequest::class.java, discardTo(S1))
      .onCommand(AlertWarningCloseNotifyRequest::class.java, discardTo(S1))
      .onCommand(ChangeCipherSpecMessageRequest::class.java, discardTo(S2))

    builder
      .forState { it.stage == S4 }
      .onCommand(ApplicationDataRequest::class.java) { state, cmd -> onStage4ReceivedApplicationData(state, cmd) }
      .onCommand(
        ChangeCipherSpecMessageRequest::class.java,
      ) { state, cmd -> onStage4ReceivedChangeCipherSpec(state, cmd) }
      .onCommand(ClientHelloRequest::class.java) { state, cmd -> onStage4ReceivedClientHelloFatal(state, cmd) }
      .onCommand(
        ClientKeyExchangeRequest::class.java,
      ) { state, cmd -> onStage4ReceivedClientKeyExchangeFatal(state, cmd) }
      .onCommand(FinishedRequest::class.java) { state, cmd -> onStage4ReceivedFinishedFatal(state, cmd) }
      .onCommand(AlertWarningCloseNotifyRequest::class.java, discard)

    // Only Received APPLICATION_DATA.
    builder
      .forState { it.stage == S5 }
      .onCommand(
        ApplicationDataRequest::class.java,
      ) { state, cmd -> onStage5ReceivedApplicationData(state, cmd) }
      // become S2
      .onCommand(ClientHelloRequest::class.java) { state, cmd -> onStage5ReceivedClientHelloFatal(state, cmd) }
      .onCommand(
        ClientKeyExchangeRequest::class.java,
      ) { state, cmd -> onStage5ReceivedClientKeyExchangeFatal(state, cmd) }
      .onCommand(FinishedRequest::class.java) { state, cmd -> onStage5ReceivedFinishedFatal(state, cmd) }
      .onCommand(ChangeCipherSpecMessageRequest::class.java, discard)
      .onCommand(AlertWarningCloseNotifyRequest::class.java, discard)

    builder
      .forAnyState()
      .onCommand(RawMessage::class.java) { state, cmd -> onRawMessage(state, cmd) }
      .onCommand(DecryptMessage::class.java) { state, cmd -> onDecryptMessage(state, cmd) }
      .onCommand(Stopped::class.java, this::onStopped)
      .onCommand(Idle::class.java, this::onIdle)
      // Stashing Other Commands
      .onAnyCommand { state, cmd ->
        context.log.debug("Stash Command: {} in Stage: {}", cmd, state.stage)
        Effect().stash()
      }

    return builder.build()
  }

  // ///////////////////////
  private fun onStage3ReceivedClientKeyExchange(
    state: State,
    cmd: ClientKeyExchangeRequest<*>,
  ): ReplyEffect<State> = TODO()

  // ///////////////////////
  private fun onStage4ReceivedApplicationData(
    state: State,
    cmd: ApplicationDataRequest,
  ): ReplyEffect<State> = TODO()

  // ///////////////////////
  private fun onStage4ReceivedChangeCipherSpec(
    state: State,
    cmd: ChangeCipherSpecMessageRequest,
  ): ReplyEffect<State> = TODO()

  // ///////////////////////
  private fun onStage4ReceivedClientHelloFatal(
    state: State,
    cmd: ClientHelloRequest,
  ): ReplyEffect<State> = TODO()

  // ///////////////////////
  private fun onStage4ReceivedClientKeyExchangeFatal(
    state: State,
    cmd: ClientKeyExchangeRequest<*>,
  ): ReplyEffect<State> = TODO()

  // ///////////////////////
  private fun onStage4ReceivedFinishedFatal(
    state: State,
    cmd: FinishedRequest,
  ): ReplyEffect<State> = TODO()

  // ///////////////////////
  private fun onStage5ReceivedApplicationData(
    state: State,
    cmd: ApplicationDataRequest,
  ): ReplyEffect<State> = TODO()

  // ///////////////////////
  private fun onStage5ReceivedClientHelloFatal(
    state: State,
    cmd: ClientHelloRequest,
  ): ReplyEffect<State> = TODO()

  // ///////////////////////
  private fun onStage5ReceivedClientKeyExchangeFatal(
    state: State,
    cmd: ClientKeyExchangeRequest<*>,
  ): ReplyEffect<State> = TODO()

  // ///////////////////////
  private fun onStage5ReceivedFinishedFatal(
    state: State,
    cmd: FinishedRequest,
  ): ReplyEffect<State> = TODO()

  // ///////////////////////

  // ///////////////////////

  /**
   * Handle a datagram packet from the seed service.
   */
  private fun onRawMessage(
    state: State,
    message: RawMessage,
  ): ReplyEffect<State> {
    context.log.trace(
      "--> Receive from peer: {}'s datagram packet [{}{}{}]",
      message.peerAddress,
      Highlight.GREEN,
      Utility.byteArray2HexStringDump(message.raw),
      Highlight.RESET,
    )
    context.log.trace("--> Current: {}", state)
    return if (message.isPlainText) {
      context.log.info("UDP detected...  ")
      val text = String(message.raw).trim()
      when (text) {
        "ClientHello1" -> Effect().reply(context.self, message.buildTestClientHello1(state.idGenerator))
        "ClientHello2" -> Effect().reply(context.self, message.buildTestClientHello2(state.idGenerator))
        else -> Effect().reply(context.self, DecryptMessage(message.raw, message.peerAddress, message.socket))
      }
    } else {
      context.log.info("DTLS detected... ")
      val records = message.toRecords(state.idGenerator)
      require(records.isNotEmpty()) { "DTLS detected but records is empty, internal server error..." }
      if (records.size == 1) {
        val record = records.first()

        return if (record.isNewClientHello) {
          processingNewClientHello(record, message.socket)
        } else {
          processRecord(record, state, message.socket)
        }
      } else {
        Effect().noReply()
      }
    }
  }

  /**
   * Process received record.
   *
   * @param record received record.
   */
  private fun processRecord(
    record: Record,
    state: State,
    socket: ActorRef<Udp.Send>,
  ): ReplyEffect<State> {
    val ctx = state.dtlsContext
    val peer = state.peerAddress
    return if (ctx == null) {
      Effect().noReply()
    } else {
      val epoch = record.epoch
      if (ctx.readEpoch == epoch) {
        // ensure, that connection is still related to record
        // and not changed by processing another record before
        if ((record.connectionId == null && peer != record.peerAddress) || peer == null) {
          val delay = TimeUnit.NANOSECONDS.toMillis(ClockUtil.nanoRealtime() - record.receiveNanos)
          context.log.debug(
            "Drop received record {}, connection changed address {} => {}! (shift {}ms)",
            record.type,
            Utility.toLog(record.peerAddress),
            Utility.toLog(peer),
            delay,
          )
          return Effect().noReply().thenUnstashAll()
        }

        context.log.trace(
          "Received DTLS record of type [{}], length: {}, [epoche:{},rseqn:{}]",
          record.type,
          record.fragmentLength,
          epoch,
          record.sequenceNumber,
        )

        record.decodeFragment(DTLSConnectionState.NULL)
        when (val dtlsMessage = record.fragment) {
          is ClientHello -> {
            return Effect().reply(
              context.self,
              ClientHelloRequest(record, dtlsMessage, peer, socket),
            )
          }

          else -> {}
        }

        Effect().noReply()
      } else {
        Effect().noReply()
      }
    }
  }

  /**
   * Process new CLIENT_HELLO message.
   *
   * Executed outside the serial execution. Checks for either a valid session
   * id or a valid cookie. If the check is passed successfully, check next, if
   * a connection for that CLIENT_HELLO already exists using the client random
   * contained in the CLIENT_HELLO message. If the connection already exists,
   * take that, otherwise create a new one and pass the execution to the
   * serial execution of that connection.
   *
   * @param record record of CLIENT_HELLO message.
   */
  private fun processingNewClientHello(
    record: Record,
    socket: ActorRef<Udp.Send>,
  ): ReplyEffect<State> {
    context.log.trace(
      "Processing new CLIENT_HELLO from peer [{}]:{}{}",
      Utility.toLog(record.peerAddress),
      Utility.LINE_SEPARATOR,
      record,
    )

    // CLIENT_HELLO with epoch 0 is not encrypted, so use DTLSConnectionState.NULL
    try {
      record.decodeFragment(DTLSConnectionState.NULL)
      val dtlsMessage = record.fragment

      if (dtlsMessage is FragmentedHandshakeMessage) {
        context.log.debug(
          "Received unsupported fragmented CLIENT_HELLO from peer {}.",
          Utility.toLog(record.peerAddress),
        )
        // Fragmented CLIENT_HELLO is not supported!
        return Effect().noReply()
      }

      return when (dtlsMessage) {
        is ClientHello ->
          Effect().reply(
            context.self,
            ClientHelloRequest(record, dtlsMessage, record.peerAddress!!, socket),
          )

        else -> Effect().stash()
      }
    } catch (e: Throwable) {
      context.log.debug(
        "Processing new CLIENT_HELLO from peer [{}] failed!",
        Utility.toLog(record.peerAddress),
        e,
      )
      return Effect().noReply()
    }
  }

  // <editor-fold desc="TEST MOCK.">

  private fun RawMessage.buildTestClientHello1(idGenerator: ConnectionIdGenerator): ClientHelloRequest {
    val clientHello =
      "16fefd0000000000000000009d010000910000000000000091fefd6528ccc584435c4f65b2619e5a" +
        "809c531d79bee3951fe2bc23a1a1eacc2508c10000002cc02bc02cc0aec0afc0acc0adc023c024c0" +
        "0ad001d002d003d005c03700a800a9c0a8c0a9c0a4c0a500ae00ff0100003b000a000a0008001700" +
        "1d001e0018000b00020100000d000600040403040100130003020200001400030202000017000000" +
        "360007066d5781b4858c"
    return buildTestClientHello(clientHello, idGenerator)
  }

  private fun RawMessage.buildTestClientHello2(idGenerator: ConnectionIdGenerator): ClientHelloRequest {
    val clientHello =
      "16fefd000000000000000100bd010000b100010000000000b1fefd6528ccc584435c4f65b2619e5a" +
        "809c531d79bee3951fe2bc23a1a1eacc2508c10020f2e99bc8659ef7a3f33c909d916f95638fedab" +
        "267d51ea3922c2da5d55486895002cc02bc02cc0aec0afc0acc0adc023c024c00ad001d002d003d0" +
        "05c03700a800a9c0a8c0a9c0a4c0a500ae00ff0100003b000a000a00080017001d001e0018000b00" +
        "020100000d000600040403040100130003020200001400030202000017000000360007066d5781b4858c"
    return buildTestClientHello(clientHello, idGenerator)
  }

  private fun RawMessage.buildTestClientHello(
    data: String,
    idGenerator: ConnectionIdGenerator,
  ): ClientHelloRequest {
    val byteArray =
      Utility.hex2ByteArray(data)!!
    val rawMessage = RawMessage(byteArray, this.peerAddress, this.socket)
    val records = rawMessage.toRecords(idGenerator)

    val record = records.first()
    record.decodeFragment(DTLSConnectionState.NULL)
    val dtlsMessage = record.fragment

    check(dtlsMessage != null && dtlsMessage is ClientHello) { "Unexpected record fragment" }
    context.log.trace("Generate a fake [Client_Hello]: {}{}", Utility.LINE_SEPARATOR, dtlsMessage)
    return ClientHelloRequest(record, dtlsMessage, this.peerAddress, this.socket)
  }

  // </editor-fold>

  private fun onDecryptMessage(
    state: State,
    message: DecryptMessage,
  ): ReplyEffect<State> {
    context.log.trace(
      "<-- send to peer: {}'s datagram packet [{}{}{}]",
      message.peerAddress,
      Highlight.CYAN,
      Utility.byteArray2HexStringDump(message.decrypt),
      Highlight.RESET,
    )
    context.log.trace("<-- Current: {}", state)
    return Effect().reply(
      message.socket,
      Udp.Send(ByteString.fromArray(message.decrypt), message.peerAddress, Udp.NoAck(null)),
    )
  }

  private fun onStopped(): ReplyEffect<State> = Effect().stop().thenNoReply()

  private fun onIdle(): ReplyEffect<State> {
    // after receive timeout
    shard.tell(ClusterSharding.Passivate(context.self))
    return Effect().noReply()
  }
}
