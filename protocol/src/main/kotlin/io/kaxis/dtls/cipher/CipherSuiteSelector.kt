/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
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
