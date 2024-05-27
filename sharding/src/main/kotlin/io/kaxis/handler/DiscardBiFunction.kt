/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
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
