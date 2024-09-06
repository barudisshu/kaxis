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
import io.lettuce.core.RedisClient
import io.lettuce.core.RedisFuture
import io.lettuce.core.TransactionResult
import org.apache.pekko.Done
import org.apache.pekko.actor.ExtendedActorSystem
import org.apache.pekko.persistence.state.DurableStateStoreProvider
import org.apache.pekko.persistence.state.scaladsl.DurableStateStore
import org.apache.pekko.persistence.state.scaladsl.DurableStateUpdateStore
import org.apache.pekko.persistence.state.scaladsl.GetObjectResult
import org.apache.pekko.serialization.Serialization
import org.apache.pekko.serialization.SerializationExtension
import org.apache.pekko.serialization.SerializerWithStringManifest
import scala.Option
import scala.Some
import scala.Tuple2
import scala.compat.java8.FutureConverters.toJava
import scala.compat.java8.FutureConverters.toScala
import scala.concurrent.Future
import scala.util.Failure
import scala.util.Success
import java.time.Duration
import java.util.concurrent.CompletionStage

class RedisStoreProvider(
  private val system: ExtendedActorSystem,
  private val config: Config,
  private val cfgPath: String,
) : DurableStateStoreProvider {
  override fun scaladslDurableStateStore(): DurableStateStore<Any> = RedisStateStore(system, config, cfgPath)

  override fun javadslDurableStateStore(): org.apache.pekko.persistence.state.javadsl.DurableStateStore<Any> =
    RedisStateStoreJava(system, config, cfgPath)

  class RedisStateStore<A>(
    private val system: ExtendedActorSystem,
    config: Config,
    cfgPath: String,
  ) : DurableStateUpdateStore<A> {
    private val impl = StateStoreImpl(system, config, cfgPath)
    private val serialization: Serialization = SerializationExtension.get(system)

    override fun upsertObject(
      persistenceId: String?,
      revision: Long,
      value: A,
      tag: String?,
    ): Future<Done> = impl.upsertObject(persistenceId, revision, serialize(value).asStorableString(), tag)

    override fun deleteObject(
      persistenceId: String?,
      revision: Long,
    ): Future<Done> = impl.deleteObject(persistenceId, revision)

    override fun deleteObject(persistenceId: String?): Future<Done> = impl.deleteObject(persistenceId)

    override fun getObject(persistenceId: String?): Future<GetObjectResult<A>> =
      impl.getObject(persistenceId).map({
        when (it) {
          is Some ->
            GetObjectResult(
              Some(deserialize<A>(SerializedBlob.fromStorableString(it.value()._1))),
              it.value()._2,
            )

          else -> GetObjectResult(Option.empty(), 0)
        }
      }, system.dispatcher)

    private fun serialize(value: A): SerializedBlob {
      val serializer = serialization.findSerializerFor(value)
      val bytes = serializer.toBinary(value)
      val manifest =
        when (serializer) {
          is SerializerWithStringManifest -> serializer.manifest(value)
          else -> null
        }
      return SerializedBlob(bytes, serializer.identifier(), manifest)
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> deserialize(serializedValue: SerializedBlob): T {
      val deserialized =
        serialization.deserialize(
          serializedValue.data,
          serializedValue.serializerId,
          serializedValue.manifest ?: "",
        )
      return when (deserialized) {
        is Success -> deserialized.value() as T
        is Failure -> throw deserialized.exception()
        else -> error("Deserialized $serializedValue failed")
      }
    }
  }

  data class SerializedBlob(
    val data: ByteArray,
    val serializerId: Int,
    val manifest: String?,
  ) {
    companion object {
      fun fromStorableString(storableString: String): SerializedBlob {
        val parts = storableString.split('|')
        val serializerId = parts[0].toInt()
        val manifest = if (parts.size > 2) parts[1] else null
        val data = parts.last().toByteArray()
        return SerializedBlob(data, serializerId, manifest)
      }
    }

    fun asStorableString(): String {
      val manifestString = manifest?.let { "|$it" } ?: ""
      return "$serializerId$manifestString|${String(data)}"
    }

    override fun equals(other: Any?): Boolean {
      if (this === other) return true
      if (javaClass != other?.javaClass) return false

      other as SerializedBlob

      if (!data.contentEquals(other.data)) return false
      if (serializerId != other.serializerId) return false
      if (manifest != other.manifest) return false

      return true
    }

    override fun hashCode(): Int {
      var result = data.contentHashCode()
      result = 31 * result + serializerId
      result = 31 * result + (manifest?.hashCode() ?: 0)
      return result
    }
  }

  class RedisStateStoreJava<A>(
    private val system: ExtendedActorSystem,
    config: Config,
    cfgPath: String,
  ) : org.apache.pekko.persistence.state.javadsl.DurableStateUpdateStore<A> {
    private val impl = RedisStateStore<A>(system, config, cfgPath)

    override fun upsertObject(
      persistenceId: String?,
      revision: Long,
      value: A,
      tag: String?,
    ): CompletionStage<Done> = toJava(impl.upsertObject(persistenceId, revision, value, tag))

    override fun deleteObject(
      persistenceId: String?,
      revision: Long,
    ): CompletionStage<Done> = toJava(impl.deleteObject(persistenceId, revision))

    override fun deleteObject(persistenceId: String?): CompletionStage<Done> = toJava(impl.deleteObject(persistenceId))

    override fun getObject(
      persistenceId: String?,
    ): CompletionStage<org.apache.pekko.persistence.state.javadsl.GetObjectResult<A>> =
      toJava(
        impl.getObject(persistenceId).map({
          it.toJava()
        }, system.dispatcher()),
      )
  }

  class StateStoreImpl(
    private val system: ExtendedActorSystem,
    config: Config,
    cfgPath: String,
  ) {
    private val redisClient = RedisClient.create(config.getString("redis.url"))
    private val connection = redisClient.connect()
    private val asyncCommands = connection.async()

    private fun insert(
      persistenceId: String?,
      value: String,
      revision: Long,
    ): RedisFuture<TransactionResult> {
      asyncCommands.multi()
      asyncCommands[persistenceId] = value
      asyncCommands["$persistenceId:revision"] = revision.toString()
      // for test
      asyncCommands.expire(persistenceId, Duration.ofSeconds(30))
      asyncCommands.expire("$persistenceId:revision", Duration.ofSeconds(30))
      return asyncCommands.exec()
    }

    fun upsertObject(
      persistenceId: String?,
      revision: Long,
      value: String,
      tag: String?,
    ): Future<Done> {
      val existingRecord = asyncCommands["$persistenceId:revision"]

      return toScala(
        existingRecord.handleAsync { record, _ ->
          if (record == null) {
            system.log().debug("upsertObject: {}:{}", persistenceId, value)
            system.log().debug("upsertObject: {}:revision:{}", persistenceId, revision)
            return@handleAsync insert(persistenceId, value, revision)
          } else {
            val existingRevision = record.toLong()
            if (revision >= existingRevision + 1) {
              system.log().debug("upsertObject: {}:{}", persistenceId, value)
              system.log().debug("upsertObject: {}:revision:{}", persistenceId, revision)
              return@handleAsync insert(persistenceId, value, revision)
            } else {
              error("Revision mismatch. Expected: ${existingRevision + 1}, Actual: $revision")
            }
          }
        },
      ).map({ Done.done() }, system.dispatcher)
    }

    fun deleteObject(
      persistenceId: String?,
      revision: Long,
    ): Future<Done> {
      val existingRecord = asyncCommands["$persistenceId:revision"]
      return toScala(
        existingRecord.handleAsync { record, _ ->
          if (record == null) {
            error("No record exists for persistence id: $persistenceId")
          } else {
            val existingRevision = record.toLong()
            if (revision >= existingRevision + 1) {
              system.log().debug("deleteObject: {}", persistenceId)
              system.log().debug("deleteObject: {}:revision", persistenceId)
              return@handleAsync insert(persistenceId, "", revision)
            } else {
              error("Revision mismatch. Expected: ${existingRevision + 1}, Actual: $revision")
            }
          }
        },
      ).map({ Done.done() }, system.dispatcher)
    }

    fun deleteObject(persistenceId: String?): Future<Done> = deleteObject(persistenceId, 0)

    fun getObject(persistenceId: String?): Future<Option<Tuple2<String, Long>>> {
      return toScala(asyncCommands[persistenceId]).map({ record ->
        return@map if (record == null) {
          null
        } else {
          val revision =
            asyncCommands["$persistenceId:revision"]
              .handleAsync { t, _ ->
                return@handleAsync t?.toLong() ?: 0
              }.toCompletableFuture()
              .get()
          system.log().debug("getObject: {}:{}", persistenceId, record)
          system.log().debug("getObject: {}:revision:{}", persistenceId, revision)
          return@map Some(Tuple2.apply(record, revision))
        }
      }, system.dispatcher)
    }
  }
}
