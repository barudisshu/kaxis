/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.cipher

fun interface CipherSuiteSelector {
  /**
   * Select cipher-suite and parameters. if no common parameter could be negotiated, use
   * [CipherSuiteParameters.generalMismatch] or [CipherSuiteParameters.certificateMismatch] to indicate the
   * mismatch cause.
   *
   * @param parameters common cipher-suites and crypto parameters. On success, the cipher-suite and parameters
   * gets selected in this argument.
   * @return `true`, if a cipher-suite and parameters could be selected, `false`, otherwise.
   */
  fun select(parameters: CipherSuiteParameters): Boolean
}
