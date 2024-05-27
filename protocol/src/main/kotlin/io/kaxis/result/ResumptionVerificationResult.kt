/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.result

import io.kaxis.dtls.ConnectionId
import io.kaxis.dtls.DTLSSession

/**
 * Result of resumption verification.
 *
 * @see ResumptionVerifier
 */
class ResumptionVerificationResult : HandshakeResult {
  /**
   * Get verified session
   */
  val session: DTLSSession?

  /**
   * Create result.
   * @param cid connection cid
   * @param session valid matching session. `null`, if no session is available or session is not valid for resumption.
   * @throws NullPointerException if cid is `null`.
   */
  constructor(cid: ConnectionId?, session: DTLSSession?) : super(cid) {
    this.session = session
  }
}
