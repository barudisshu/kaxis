/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
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
