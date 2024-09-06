/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.serialization

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.deser.std.StdDeserializer
import com.fasterxml.jackson.databind.module.SimpleModule
import com.fasterxml.jackson.databind.ser.std.StdSerializer
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import io.kaxis.dtls.DTLSContext
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.SerializationUtil
import java.net.InetSocketAddress

/**
 * @see JavaTimeModule as an example.
 */
class KaxisJacksonModule : SimpleModule() {
  init {
    // First deserializers
    addDeserializer(
      InetSocketAddress::class.java,
      object : StdDeserializer<InetSocketAddress>(InetSocketAddress::class.java) {
        override fun deserialize(
          p: JsonParser?,
          ctxt: DeserializationContext?,
        ): InetSocketAddress {
          requireNotNull(p) { "JsonParser must not be null!" }
          val address = p.binaryValue
          val reader = DatagramReader(address)
          return SerializationUtil.readAddress(reader)
            ?: throw IllegalStateException("Fail to deserializer NetSocketAddress from binary!!")
        }
      },
    )

    addDeserializer(
      DTLSContext::class.java,
      object : StdDeserializer<DTLSContext>(DTLSContext::class.java) {
        override fun deserialize(
          p: JsonParser?,
          ctxt: DeserializationContext?,
        ): DTLSContext {
          requireNotNull(p) { "JsonParser must not be null!" }
          val dtlsContext = p.binaryValue
          val reader = DatagramReader(dtlsContext)
          return DTLSContext.fromReader(reader)
            ?: throw IllegalStateException("Fail to deserializer DTLSContext from binary!!")
        }
      },
    )

    // then serializers:
    addSerializer(
      InetSocketAddress::class.java,
      object : StdSerializer<InetSocketAddress>(InetSocketAddress::class.java) {
        override fun serialize(
          address: InetSocketAddress?,
          gen: JsonGenerator?,
          provider: SerializerProvider?,
        ) {
          requireNotNull(address) { "InetSocketAddress must not be null!" }
          requireNotNull(gen) { "JsonGenerator must not be null!" }

          val writer = DatagramWriter()
          SerializationUtil.write(writer, address)
          val data = writer.toByteArray()
          gen.writeBinary(data)
        }
      },
    )

    addSerializer(
      DTLSContext::class.java,
      object : StdSerializer<DTLSContext>(DTLSContext::class.java) {
        override fun serialize(
          dtlsContext: DTLSContext?,
          gen: JsonGenerator?,
          provider: SerializerProvider?,
        ) {
          requireNotNull(dtlsContext) { "DTLSContext must not be null!" }
          requireNotNull(gen) { "JsonGenerator must not be null!" }

          val writer = DatagramWriter()
          dtlsContext.writeTo(writer)
          val data = writer.toByteArray()
          gen.writeBinary(data)
        }
      },
    )
  }
}
