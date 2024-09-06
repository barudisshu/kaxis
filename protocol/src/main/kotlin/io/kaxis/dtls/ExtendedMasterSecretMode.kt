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

/**
 * Extended master secret mode.
 *
 * See [RFC 7672](https://tools.ietf.org/html/rfc7627) for additional details.
 *
 * [RFC 7925, 16. Session Hash](https://tools.ietf.org/html/rfc7925#section-16) recommends to use this extension. Please, obey the different behavior on session
 * resumption according [RFC 7672, 5.3. Client and Server Behavior: Abbreviated Handshake](https://tools.ietf.org/html/rfc7627#section-5.3), if one side doesn't support this extension.
 */
enum class ExtendedMasterSecretMode {
  /**
   * Disable the use of the extended master secret.
   */
  NONE,

  /**
   * optionally use the extended master secret. Session without extended master secret may be resumed. Not RFC 7627 compliant.
   */
  OPTIONAL,

  /**
   * Enable the use of the extended master secret. Session without extended master secret can not be
   * resumed. The server will not asign a sesion ID, if the client doesn't use the extended master secret. That
   * prevents such a client from accidentally resume the session. RFC 7627 compliant.
   */
  ENABLED,

  /**
   * Requires the use of the extended master secret.
   */
  REQUIRED,

  ;

  /**
   * Checks, if provided mode is contained in this mode.
   * @param mode mode to be compared
   * @return `true`, if the [ordinal] of this mode is larger or equal to the one of the provided mode. `false`, otherwise.
   */
  fun equals(mode: ExtendedMasterSecretMode): Boolean {
    return ordinal >= mode.ordinal
  }
}
