/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
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
