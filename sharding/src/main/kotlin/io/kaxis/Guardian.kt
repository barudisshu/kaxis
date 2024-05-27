/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis

import io.kaxis.extensions.toEntity
import io.kaxis.fsm.RawMessage
import org.apache.pekko.actor.AbstractActor
import org.apache.pekko.actor.ActorRef
import org.apache.pekko.actor.PoisonPill
import org.apache.pekko.actor.typed.Behavior
import org.apache.pekko.actor.typed.javadsl.*
import org.apache.pekko.cluster.sharding.typed.javadsl.ClusterSharding
import org.apache.pekko.event.Logging
import org.apache.pekko.event.LoggingAdapter
import org.apache.pekko.io.Udp
import org.apache.pekko.io.UdpMessage
import java.net.InetSocketAddress

class Guardian private constructor() : AbstractActor() {
  private val log: LoggingAdapter = Logging.getLogger(context.system, this)

  private lateinit var sharding: ClusterSharding

  override fun preStart() {
    super.preStart()
    sharding = ClusterSharding.get(Adapter.toTyped(context.system))
  }

  companion object {
    const val NAME = "Guardian"
    const val TYPED = "Binding"

    private fun create(): org.apache.pekko.actor.Props =
      org.apache.pekko.actor.Props
        .create(Guardian::class.java)

    fun create(
      host: String,
      udpPort: Int,
    ): Behavior<Any> = Typed.create(host, udpPort)

    internal class Typed(
      context: org.apache.pekko.actor.typed.javadsl.ActorContext<Any>?,
      private val classic: ActorRef,
    ) : AbstractBehavior<Any>(context) {
      companion object {
        fun create(
          host: String,
          port: Int,
        ): Behavior<Any> {
          return Behaviors.setup { context ->
            val remote = InetSocketAddress(host, port)
            val classic = context.classicActorContext().actorOf(create(), NAME)
            context.classicActorContext().watch(classic)
            val mgr = Udp.get(context.system.classicSystem()).manager
            mgr.tell(UdpMessage.bind(classic, remote), classic)
            return@setup Typed(context, classic)
          }
        }
      }

      override fun createReceive(): org.apache.pekko.actor.typed.javadsl.Receive<Any> =
        newReceiveBuilder()
          .onMessage(Udp.Unbound::class.java) { onUnbound() }
          .onSignal(org.apache.pekko.actor.typed.Terminated::class.java) { Behaviors.stopped() }
          .build()

      private fun onUnbound(): Behavior<Any> {
        Adapter.stop(context, classic)
        return this
      }
    }
  }

  override fun createReceive(): Receive =
    receiveBuilder()
      .match(Udp.Bound::class.java) {
        log.debug("{} address bounded.", it.localAddress())
        context.become(ready(sender))
      }.matchAny {
        log.error("emergency fault")
        self().tell(PoisonPill.getInstance(), self)
      }.build()

  private fun ready(socket: ActorRef): Receive =
    receiveBuilder()
      .match(Udp.Received::class.java) {
        sharding
          .entityRefFor(RecordLayer.TypeKey, it.sender().toEntity())
          .tell(RawMessage(it.data().toArrayUnsafe(), it.sender(), Adapter.toTyped(socket)))
      }.matchEquals(UdpMessage.unbind()) { socket.tell(it, self) }
      .match(Udp.Unbound::class.java) { context.stop(self) }
      .build()
}
