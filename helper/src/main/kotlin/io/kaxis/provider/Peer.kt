/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.provider

import org.bouncycastle.tls.TlsCloseable
import java.io.IOException

/**
 * The Peer side which holding resource shall be auto-closeable.
 * @author galudisu
 */
interface Peer : AutoCloseable, TlsCloseable {
  /**
   * Emit message to peer.
   */
  @Throws(IOException::class)
  fun emit(
    buf: ByteArray,
    off: Int,
    len: Int,
  )
}
