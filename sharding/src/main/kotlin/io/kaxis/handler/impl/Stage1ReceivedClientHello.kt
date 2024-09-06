/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.handler.impl

import io.kaxis.anno.GreenLine
import io.kaxis.dtls.message.handshake.ClientHello
import io.kaxis.fsm.ClientHelloRequest
import io.kaxis.fsm.Command
import io.kaxis.fsm.DecryptMessage
import io.kaxis.fsm.State
import io.kaxis.fsm.State.Stage.S2
import io.kaxis.fsm.State.Stage.S3
import io.kaxis.handler.StageBiFunction
import org.apache.pekko.actor.typed.javadsl.ActorContext
import org.apache.pekko.persistence.typed.state.javadsl.EffectFactories
import org.apache.pekko.persistence.typed.state.javadsl.ReplyEffect

/**
 * This the happy path of the handshake. This is normal behavior.
 *
 * See [RFC 6347](https://tools.ietf.org/html/rfc6347#section-4.2.1) for the definition.
 *
 * The first message each side transmits in each handshake always has `message_seq = 0`. Whenever each new
 * message is generated, the `message_seq` in incremented by one. Note that in the case of a rehandshake, this
 * implies that the `HelloRequest` will have `message_seq = 0` and the `ServerHello` will have `message_seq = 1`.
 * When a message is retransmitted, the same `message_seq` value is used. For example:
 *
 * ```
 *  Client                             Server
 *  ------                             ------
 *  ClientHello (seq=0)  ------>
 *
 *                          X<-- HelloVerifyRequest (seq=0)
 *                                          (lost)
 *
 *  [Timer Expires]
 *
 *  ClientHello (seq=0)  ------>
 *  (retransmit)
 *
 *                       <------ HelloVerifyRequest (seq=0)
 *
 *  ClientHello (seq=1)  ------>
 *  (with cookie)
 *
 *                       <------        ServerHello (seq=1)
 *                       <------        Certificate (seq=2)
 *                       <------    ServerHelloDone (seq=3) *
 * ```
 */
class Stage1ReceivedClientHello(
  context: ActorContext<Command>,
  effect: EffectFactories<State>,
) : StageBiFunction<Command, ClientHelloRequest, ClientHello>(context, effect) {
  @GreenLine("ClientHello/SERVER_HELLO|CERTIFICATE|SERVER_HELLO_DONE")
  override fun handle(
    state: State,
    cmd: ClientHelloRequest,
  ): ReplyEffect<State> {
//    initializeDtlsContext(DTLSContext(message.messageSeq.toLong(), supportKeyMaterialExport))
    initializePeerAddress(cmd.peerAddress)
    initializeCid(decodedRecord.connectionId)
//    setCurrentReadState()

    val helloVerifyRequestRecord = generateHelloVerifyRequest(message)

    if (helloVerifyRequestRecord == null) {
      receivedClientHello(message)

      val datagramPackets = generateFragmentFromPendingFlight()
      return effect
        .persist(state goto S3)
        .thenRun {
          datagramPackets.forEach { datagramPacket ->
            self.tell(DecryptMessage(datagramPacket.data, peerAddress, cmd.socket))
          }
        }.thenNoReply()
    } else {
      return effect.persist(state goto S2).thenNoReply()
    }
  }
}
