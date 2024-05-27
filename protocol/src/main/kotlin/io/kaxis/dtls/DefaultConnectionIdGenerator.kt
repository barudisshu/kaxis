/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls

import io.kaxis.dtls.cipher.RandomManager
import io.kaxis.util.DatagramReader

class DefaultConnectionIdGenerator(private val connectionIdLength: Int) : ConnectionIdGenerator {
  init {
    require(connectionIdLength >= 0) { "cid length must not be less than 0 bytes!" }
  }

  override fun useConnectionId(): Boolean {
    return connectionIdLength > 0
  }

  override fun createConnectionId(): ConnectionId? {
    return if (useConnectionId()) {
      val cidBytes = ByteArray(connectionIdLength)
      RandomManager.currentRandom().nextBytes(cidBytes)
      ConnectionId(cidBytes)
    } else {
      null
    }
  }

  override fun read(reader: DatagramReader): ConnectionId? {
    return if (useConnectionId()) {
      ConnectionId(reader.readBytes(connectionIdLength))
    } else {
      null
    }
  }
}
