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
