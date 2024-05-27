/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls

import io.kaxis.result.HandshakeResult

/**
 * Handler for asynchronous handshake results.
 *
 * The implementation must take care that the calling thread is undefined.
 */
fun interface HandshakeResultHandler {
  /**
   * Apply handshake result.
   * @param handshakeResult handshake result
   */
  fun apply(handshakeResult: HandshakeResult)
}
