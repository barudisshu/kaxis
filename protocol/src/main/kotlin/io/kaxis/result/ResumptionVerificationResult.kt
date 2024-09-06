/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
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
