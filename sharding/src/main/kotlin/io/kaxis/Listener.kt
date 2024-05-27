/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis

import org.apache.pekko.actor.typed.ActorRef
import org.apache.pekko.actor.typed.Behavior
import org.apache.pekko.actor.typed.javadsl.AbstractBehavior
import org.apache.pekko.actor.typed.javadsl.ActorContext
import org.apache.pekko.actor.typed.javadsl.Behaviors
import org.apache.pekko.actor.typed.javadsl.Receive
import org.apache.pekko.cluster.ClusterEvent.*
import org.apache.pekko.cluster.typed.Cluster
import org.apache.pekko.cluster.typed.Subscribe

/**
 * Cluster listener.
 * @author galudisu
 */
class Listener private constructor(
  context: ActorContext<Event>?,
) : AbstractBehavior<Listener.Event>(context) {
  companion object {
    const val NAME = "Listener"

    fun create(): Behavior<Event> = Behaviors.setup { Listener(it) }
  }

  interface Event : CborSerializable

  // internal adapted cluster events only
  internal class ReachabilityChange(
    val reachabilityEvent: ReachabilityEvent,
  ) : Event

  internal class MemberChange(
    val event: MemberEvent,
  ) : Event

  override fun createReceive(): Receive<Event> {
    val memberEventAdapter: ActorRef<MemberEvent> = context.messageAdapter(MemberEvent::class.java) { MemberChange(it) }
    Cluster.createExtension(context.system).subscriptions().tell(Subscribe(memberEventAdapter, MemberEvent::class.java))

    val reachabilityAdapter = context.messageAdapter(ReachabilityEvent::class.java) { ReachabilityChange(it) }
    Cluster
      .createExtension(context.system)
      .subscriptions()
      .tell(Subscribe(reachabilityAdapter, ReachabilityEvent::class.java))

    return newReceiveBuilder()
      .onMessage(ReachabilityChange::class.java, this::onReachabilityChange)
      .onMessage(MemberChange::class.java, this::onMemberChange)
      .build()
  }

  private fun onReachabilityChange(reachabilityChange: ReachabilityChange): Behavior<Event> {
    when (val event = reachabilityChange.reachabilityEvent) {
      is UnreachableMember ->
        context.log.info("Member detected as unreachable: {}", event.member())

      is ReachableMember ->
        context.log.info("Member back to reachable: {}", event.member())

      else -> error("Un-recognize event")
    }
    return Behaviors.same()
  }

  private fun onMemberChange(changeEvent: MemberChange): Behavior<Event> {
    when (val event = changeEvent.event) {
      is MemberUp ->
        context.log.info("Member is Up: {}", event.member().address())

      is MemberRemoved -> {
        context.log.info("Member is Removed: {} after {}", event.member().address(), event.previousStatus())
      }

      else -> {
        // ignore
      }
    }
    return Behaviors.same()
  }
}
