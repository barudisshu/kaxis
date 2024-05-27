/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.config

/**
 * Certificate authentication mode of other peer. Used on the server-side to request a client to authenticate by a
 * certificate. On the client-side only [NONE] or [NEEDED] is supported depending on the used cipher suite.
 *
 * @param useCertificateRequest On server-side use a Certificate Request for this authentication mode. `true`, if a certificate is requested, `false`, otherwise. [RFC 5246, 7.4.4.4. Certificate Request](https://tools.ietf.org/html/rfc5246#section-7.4.4)
 */
enum class CertificateAuthenticationMode(val useCertificateRequest: Boolean = true) {
  /**
   * Don't use a certificate for authentication. On server side, don't request a client certificate. Considered to
   * authenticate using another mechanism.
   */
  NONE(false),

  /**
   * Use a certificate for optional authentication. Don't fail on an empty certificate, but it is considered to
   * authenticate using another mechanism. On server side, request a client certificate.
   */
  WANTED(true),

  /**
   * Use a certificate for authentication. Fail on an empty certificate. On server side, request a client certificate.
   */
  NEEDED(true),
}
