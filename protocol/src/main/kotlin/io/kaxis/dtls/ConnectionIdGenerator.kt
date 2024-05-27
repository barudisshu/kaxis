/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls

import io.kaxis.util.DatagramReader

interface ConnectionIdGenerator {
  fun useConnectionId(): Boolean

  fun createConnectionId(): ConnectionId?

  fun read(reader: DatagramReader): ConnectionId?
}
