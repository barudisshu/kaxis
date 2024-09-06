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
