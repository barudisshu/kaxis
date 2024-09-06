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
 * Certificate types as defined in the [IANA registry](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml).
 */
enum class CertificateType(val code: Int, val isSupported: Boolean) {
  // values as defined by IANA TLS Certificate Types registry
  X_509(0, true),
  OPEN_PGP(1, false),
  RAW_PUBLIC_KEY(2, true),
  ;

  companion object {
    fun getTypeFromCode(code: Int): CertificateType? {
      return when (code) {
        0 -> X_509
        1 -> OPEN_PGP
        2 -> RAW_PUBLIC_KEY
        else -> null
      }
    }
  }
}
