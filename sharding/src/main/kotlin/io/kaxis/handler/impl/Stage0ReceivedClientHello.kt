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
import io.kaxis.dtls.DTLSContext
import io.kaxis.dtls.message.handshake.ClientHello
import io.kaxis.fsm.ClientHelloRequest
import io.kaxis.fsm.Command
import io.kaxis.fsm.DecryptMessage
import io.kaxis.fsm.State
import io.kaxis.fsm.State.Stage.S1
import io.kaxis.handler.StageBiFunction
import io.kaxis.util.Utility
import org.apache.pekko.actor.typed.javadsl.ActorContext
import org.apache.pekko.persistence.typed.state.javadsl.EffectFactories
import org.apache.pekko.persistence.typed.state.javadsl.ReplyEffect

/**
 * This the happy path of the handshake. This is normal behavior.
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
 */
class Stage0ReceivedClientHello(
  context: ActorContext<Command>,
  effect: EffectFactories<State>,
) : StageBiFunction<Command, ClientHelloRequest, ClientHello>(context, effect) {
  @GreenLine("ClientHello/HELLO_VERIFY_REQUEST")
  override fun handle(
    state: State,
    cmd: ClientHelloRequest,
  ): ReplyEffect<State> {
    // At the very beginning, initialize `DTLSContext`
    initializeDtlsContext(DTLSContext(message.messageSeq.toLong(), supportKeyMaterialExport))
    initializePeerAddress(cmd.peerAddress)
    if (decodedRecord.connectionId != null) {
      initializeCid(decodedRecord.connectionId)
    } else {
      val cid = state.idGenerator.createConnectionId()
      decodedRecord.connectionId = cid
      initializeCid(cid)
    }
    val helloVerifyRequestRecord = generateHelloVerifyRequest(message)

    return if (helloVerifyRequestRecord != null) {
      effect
        .persist(state goto S1)
        .thenReply(self) { _ ->
          log.debug(
            "Peer: {} will receive a [HelloVerifyRequest]:{}{}",
            cmd.peerAddress,
            Utility.LINE_SEPARATOR,
            helloVerifyRequestRecord,
          )
          DecryptMessage(helloVerifyRequestRecord.toByteArray(), cmd.peerAddress, cmd.socket)
        }
    } else {
      effect.persist(state goto S1).thenNoReply().thenUnstashAll()
    }
  }
}
