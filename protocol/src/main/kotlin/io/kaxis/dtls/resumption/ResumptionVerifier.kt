/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.resumption

import io.kaxis.dtls.ConnectionId
import io.kaxis.dtls.HandshakeResultHandler
import io.kaxis.dtls.ServerNames
import io.kaxis.dtls.SessionId
import io.kaxis.result.ResumptionVerificationResult

/**
 * Resumption verifier.
 *
 * If a client provided a session id in the `CLIENT_HELLO`, this verifier is used to verify,
 * if there is a valid session to resume. An implementation may check a maximum time, or,
 * if the credentials are expired (e.g. X.509 valid range). The default verifier will just
 * checks, if a DTLS session with that session id is available in the [ResumptionSupportingConnectionState].
 */
interface ResumptionVerifier {
  /**
   * Checks, if the session id is matching and the `CLIENT_HELLO` may bypass the cookie validation
   * without using a `HELLO_VERIFY_REQUEST`.
   *
   * **NOTE**: this function must return immediately.
   *
   * @param sessionId session id
   * @return `true`, if valid and no `HELLO_VERIFY_REQUEST` is required, `false`, otherwise.
   */
  fun skipRequestHelloVerify(sessionId: SessionId): Boolean

  /**
   * Verify resumption request. Either return the result, or `null` and process the request
   * asynchronously. The [ResumptionVerificationResult] must contain the CID, and the DTLS
   * session, if available. If the result is not returned, it is passed asynchronously to
   * the result handler, provided during initialization by [setResultHandler].
   *
   * @param cid connection id
   * @param serverNames server names
   * @param sessionId session id
   *
   * @return resumption result, or `null`, if the result is provided asynchronous.
   */
  fun verifyResumptionRequest(
    cid: ConnectionId,
    serverNames: ServerNames,
    sessionId: SessionId,
  ): ResumptionVerificationResult

  /**
   * Set the handler for asynchronous master secret results. called during initialization.
   *
   * Synchronous implementations may just ignore this using an empty implementation.
   *
   * @param resultHandler handler for asynchronous master secret results. This handler
   * MUST NOT be called from the thread calling [verifyResumptionRequest], instead just
   * return the result there.
   */
  fun setResultHandler(resultHandler: HandshakeResultHandler)
}
