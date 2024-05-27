/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.store

import io.kaxis.dtls.ConnectionId
import io.kaxis.dtls.DTLSContext
import io.kaxis.fsm.State
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.SerializationUtil
import io.kaxis.util.Utility
import org.apache.pekko.actor.ExtendedActorSystem
import org.apache.pekko.serialization.JSerializer

/**
 *  ```
 * (State, Command) => State
 * ```
 * State Serializer.
 *
 * The current state is always stored in the database. Since only the latest state is stored, we don't have
 * access to any of the history of changes, unlike event sourced storage. We don't need to replay any event
 * even if the node is crash while impl DTLS server we must be aware of the security.
 */
class StateSerializer(
  system: ExtendedActorSystem,
) : JSerializer() {
  companion object {
    private const val STATE_VERSION = 1

    fun toByteArray(state: State?): ByteArray {
      val writer = DatagramWriter()
      if (state == null) {
        SerializationUtil.writeNoItem(writer)
      } else {
        val position = SerializationUtil.writeStartItem(writer, STATE_VERSION, Short.SIZE_BITS)
        writer.write(state.stage.stage, Byte.SIZE_BITS)

        writer.writeByte(if (state.resumptionRequired) 1.toByte() else 0.toByte())
        SerializationUtil.write(writer, state.peerAddress)
        if (state.cid != null && state.cid!!.isNotEmpty()) {
          writer.writeByte(1.toByte())
          writer.writeVarBytes(state.cid!!.byteArray, Byte.SIZE_BITS)
        } else {
          writer.writeByte(0.toByte())
        }

        if (state.dtlsContext != null) {
          val contextWriter = DatagramWriter()
          state.dtlsContext!!.writeTo(contextWriter)
          val contextData = contextWriter.toByteArray()
          writer.writeBytes(contextData)
        }
        SerializationUtil.writeFinishedItem(writer, position, Short.SIZE_BITS)
      }
      return writer.toByteArray()
    }

    fun toState(byteArray: ByteArray?): State? =
      if (byteArray == null || byteArray.isEmpty()) {
        null
      } else {
        val reader = DatagramReader(byteArray)
        val length = SerializationUtil.readStartItem(reader, STATE_VERSION, Short.SIZE_BITS)
        if (length <= 0) {
          null
        } else {
          val rangeReader = reader.createRangeReader(length)
          val stage = rangeReader.read(Byte.SIZE_BITS)

          val resumptionRequired = rangeReader.readNextByte() == 1.toByte()
          val peerAddress = SerializationUtil.readAddress(rangeReader)

          var cid: ConnectionId? = null
          if (rangeReader.readNextByte() == 1.toByte()) {
            val data = rangeReader.readVarBytes(Byte.SIZE_BITS)
            if (data != null) {
              cid = ConnectionId(data)
            }
          }

          var dtlsContext: DTLSContext? = null
          if (rangeReader.bytesAvailable()) {
            val contextData = rangeReader.readBytesLeft()
            val contextReader = DatagramReader(contextData)
            dtlsContext = DTLSContext.fromReader(contextReader)
          }
          rangeReader.assertFinished("dtls-state")

          val state = State(State.Stage.fromState(stage))
          state.resumptionRequired = resumptionRequired
          state.peerAddress = peerAddress
          state.cid = cid
          state.dtlsContext = dtlsContext

          state
        }
      }
  }

  private val log = system.log()

  override fun includeManifest(): Boolean = false

  override fun identifier(): Int = 9999

  override fun toBinary(o: Any?): ByteArray =
    when (o) {
      is State? -> toByteArray(o)
      else -> throw IllegalArgumentException("Can't serialize object of type ${o?.javaClass} in [${javaClass.name}]")
    }

  /**
   * @param bytes [State] binary data.
   * @param manifest always `null` actually.
   */
  override fun fromBinaryJava(
    bytes: ByteArray?,
    manifest: Class<*>?,
  ): Any {
    val state = toState(bytes)
    if (state == null) {
      log.error("Unable to deserialize state [${Utility.byteArray2HexString(bytes)}]")
      throw IllegalArgumentException("Unable to handle serialize data: ${Utility.byteArray2HexString(bytes)}")
    } else {
      return state
    }
  }
}
