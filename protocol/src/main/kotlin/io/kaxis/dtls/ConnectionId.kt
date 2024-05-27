/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls

import io.kaxis.Bytes

/**
 * implementation of DTLS connection id. See also [RFC 9146, Connection identifier for DTLS 1.2](https://www.rfc-editor.org/rfc/rfc9146.html).
 */
class ConnectionId(connectionId: ByteArray?) : Bytes(connectionId) {
  companion object {
    val EMPTY: ConnectionId = ConnectionId(EMPTY_BYTES)

    /**
     * Check, if provided generator supports cid. Any none `null` generator supports cid. This check is therefore
     * equivalent to genrator != `null`.
     * @param generator cid generator.
     * @return `true`, if the provided genrator supports cid, `false`, if not.
     */
    fun supportsConnectionId(generator: ConnectionIdGenerator?): Boolean = generator != null

    /**
     * Check, if provided generator use cid.
     * @param generator cid generator.
     * @return `true`, if the provided generator use cid, `false`, if not.
     */
    fun useConnectionId(generator: ConnectionIdGenerator?): Boolean = generator != null && generator.useConnectionId()

    /**
     * Check, if provided cid is used for records. Only none [isEmpty] cids are used for records.
     * @param cid cid
     * @return `true`, if the provided cid is used for records, `false`, if not.
     */
    fun useConnectionId(cid: ConnectionId?): Boolean = cid != null && cid.isNotEmpty()
  }

  override fun toString(): String {
    return StringBuilder("CID=").append(asString).toString()
  }
}
