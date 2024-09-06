/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

@file:JvmName("Application")

package io.kaxis

import com.typesafe.config.Config
import com.typesafe.config.ConfigFactory
import org.apache.pekko.actor.AddressFromURIString
import org.apache.pekko.actor.typed.ActorSystem
import org.apache.pekko.actor.typed.Behavior
import org.apache.pekko.actor.typed.javadsl.Behaviors
import org.apache.pekko.management.javadsl.PekkoManagement
import java.net.InetAddress
import java.net.MalformedURLException

class Application {
  companion object {
    private object RootBehavior {
      const val NAME = "Kaxis"

      @Suppress("UNCHECKED_CAST")
      @JvmStatic
      fun create(
        host: String,
        udpPort: Int,
      ): Behavior<Unit> =
        Behaviors.setup {
          val system = it.system as ActorSystem<Unit>
          // Sharding actor
          RecordLayer.initSharding(system)

          // udp server...
          // udp classic network actor to bind each port.
          it.spawn(Guardian.create(host, udpPort), Guardian.TYPED)
          // Create an actor that handles cluster domain events
          it.spawn(Listener.create(), Listener.NAME)

          return@setup Behaviors.empty()
        }
    }

    @Throws(MalformedURLException::class)
    @JvmStatic
    fun main(args: Array<String>?) {
      val seedNodePorts: List<Int> =
        ConfigFactory
          .load()
          .getStringList("pekko.cluster.seed-nodes")
          .mapNotNull(AddressFromURIString::parse)
          .map { it.port.get() }
          .toList()

      require(seedNodePorts.isNotEmpty()) { "Fail to parse seed node address" }

      // Either use a single port provided by the user
      // Or start each listed seed nodes port plus one node on a random port in this single JVM if the user
      // didn't provide args for the app
      // In a production application, you wouldn't start multiple ActorSystem instances in the
      // same JVM, here we do it to simplify running a sample cluster from a single main method.
      val port0 = args?.firstOrNull()
      var ports =
        if (port0 != null) {
          listOf(port0.toInt())
        } else {
          (seedNodePorts + 0)
        }

      val podName = System.getenv("POD_NAME")
      val host: String

      if (podName == null) {
        // Local environment
        host = InetAddress.getByName(null).hostName
      } else {
        // K8S environment
        host = podName
        ports = listOf(ports.first())
      }

      for (port in ports) {
        val config = configWithPort(port)
        val httpPort = if (port > 0) 1000 + port else 0
        // Create an Pekko system
        val actorSystem = ActorSystem.create(RootBehavior.create(host, httpPort), RootBehavior.NAME, config)
        PekkoManagement.get(actorSystem).start()
      }
    }

    @JvmStatic
    private fun configWithPort(port: Int): Config {
      val overrides = hashMapOf<String, Any?>()
      overrides["pekko.remote.artery.canonical.port"] = port
      overrides["pekko.management.http.port"] = 2000 + port
      overrides["pekko.management.http.bind-port"] = 2000 + port
      return ConfigFactory.parseMap(overrides).withFallback(ConfigFactory.load())
    }
  }
}
