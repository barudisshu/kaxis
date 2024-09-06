/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.store

import com.typesafe.config.Config
import org.apache.pekko.Done
import org.apache.pekko.actor.ExtendedActorSystem
import org.apache.pekko.persistence.state.DurableStateStoreProvider
import org.apache.pekko.persistence.state.scaladsl.DurableStateStore
import org.apache.pekko.persistence.state.scaladsl.DurableStateUpdateStore
import org.apache.pekko.persistence.state.scaladsl.GetObjectResult
import scala.concurrent.Future
import java.util.concurrent.CompletionStage

class EmbedClusterStoreProvider(
  private val system: ExtendedActorSystem,
  private val config: Config,
  private val cfgPath: String,
) : DurableStateStoreProvider {
  override fun scaladslDurableStateStore(): DurableStateStore<Any> = EmbedClusterStore(system, config, cfgPath)

  override fun javadslDurableStateStore(): org.apache.pekko.persistence.state.javadsl.DurableStateStore<Any> =
    EmbedClusterStoreJava(system, config, cfgPath)

  class EmbedClusterStore<A>(
    private val system: ExtendedActorSystem,
    config: Config,
    cfgPath: String,
  ) : DurableStateUpdateStore<A> {
    override fun getObject(persistenceId: String?): Future<GetObjectResult<A>> {
      TODO("Not yet implemented")
    }

    override fun upsertObject(
      persistenceId: String?,
      revision: Long,
      value: A,
      tag: String?,
    ): Future<Done> {
      TODO("Not yet implemented")
    }

    override fun deleteObject(
      persistenceId: String?,
      revision: Long,
    ): Future<Done> {
      TODO("Not yet implemented")
    }

    override fun deleteObject(persistenceId: String?): Future<Done> {
      TODO("Not yet implemented")
    }
  }

  class EmbedClusterStoreJava<A>(
    private val system: ExtendedActorSystem,
    config: Config,
    cfgPath: String,
  ) : org.apache.pekko.persistence.state.javadsl.DurableStateUpdateStore<A> {
    override fun getObject(
      persistenceId: String?,
    ): CompletionStage<org.apache.pekko.persistence.state.javadsl.GetObjectResult<A>> {
      TODO("Not yet implemented")
    }

    override fun upsertObject(
      persistenceId: String?,
      revision: Long,
      value: A,
      tag: String?,
    ): CompletionStage<Done> {
      TODO("Not yet implemented")
    }

    override fun deleteObject(
      persistenceId: String?,
      revision: Long,
    ): CompletionStage<Done> {
      TODO("Not yet implemented")
    }

    override fun deleteObject(persistenceId: String?): CompletionStage<Done> {
      TODO("Not yet implemented")
    }
  }
}
