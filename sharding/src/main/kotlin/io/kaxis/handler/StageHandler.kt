/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.handler

import io.kaxis.Configuration
import io.kaxis.fsm.Command
import io.kaxis.fsm.State
import org.apache.pekko.persistence.typed.state.javadsl.ReplyEffect

sealed interface StageHandler<C : Command> : Configuration {
  fun handle(
    state: State,
    cmd: C,
  ): ReplyEffect<State>
}
