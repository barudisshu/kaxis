/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.handler

import io.kaxis.dtls.DTLSMessage
import io.kaxis.fsm.Command
import io.kaxis.fsm.Recipient
import io.kaxis.fsm.State
import org.apache.pekko.actor.typed.javadsl.ActorContext
import org.apache.pekko.persistence.typed.state.javadsl.EffectFactories
import org.apache.pekko.persistence.typed.state.javadsl.ReplyEffect

class DiscardBiFunction(
  context: ActorContext<Command>,
  effect: EffectFactories<State>,
) : StageBiFunction<Command, Recipient<DTLSMessage>, DTLSMessage>(context, effect) {
  override fun handle(
    state: State,
    cmd: Recipient<DTLSMessage>,
  ): ReplyEffect<State> {
    log.debug("Command: {} discarded in stage: {}", cmd, state.stage)
    return effect.noReply()
  }
}
