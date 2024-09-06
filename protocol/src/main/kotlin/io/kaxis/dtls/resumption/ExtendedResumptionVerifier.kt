/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.resumption

import io.kaxis.dtls.ExtendedMasterSecretMode
import io.kaxis.dtls.message.handshake.ClientHello

/**
 * Extended Resumption verifier.
 *
 * An extended resumption verifier checks additionally, if no fallback
 * to a full handshake is required.
 */
interface ExtendedResumptionVerifier : ResumptionVerifier {
  /**
   * Checks, if the session id is matching and no fallback to a full handshake
   * is required. If so, the `CLIENT_HELLO` may bypass the cookie validation
   * without using a `HELLO_VERIFY_REQUEST`.
   *
   * **NOTE**: this function must return immediately.
   *
   * @param clientHello client hello message
   * @param sniEnabled `true`, if SNI is enabled, `false`, otherwise.
   * @param extendedMasterSecretMode the extended master secret mode.
   * @return `true`, if valid and no `HELLO_VERIFY_REQUEST` is required,
   * `false`, otherwise.
   */
  fun skipRequestHelloVerify(
    clientHello: ClientHello,
    sniEnabled: Boolean,
    extendedMasterSecretMode: ExtendedMasterSecretMode,
  )
}
