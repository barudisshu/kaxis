/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.result

import io.kaxis.dtls.ConnectionId

/**
 * Handshake result for optionally asynchronous functions.
 *
 * @param cid Connection id of the connection.
 */
open class HandshakeResult(val cid: ConnectionId?) {
  init {
    requireNotNull(cid) { "cid must not be null!" }
  }
}
