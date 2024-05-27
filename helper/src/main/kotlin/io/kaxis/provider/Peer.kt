/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
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
