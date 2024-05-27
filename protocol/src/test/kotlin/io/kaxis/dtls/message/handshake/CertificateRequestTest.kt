/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.message.handshake

import io.kaxis.dtls.DtlsTestTools
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

internal class CertificateRequestTest {
  /**
   * Verifies that an ECDSA key is considered incompatible with the _dss_fixed_dh_ certificate type.
   */
  @Test
  fun testIsSupportedKeyTypeFailsForUnsupportedKeyAlgorithm() {
    val key = DtlsTestTools.getClientPublicKey()
    val req = CertificateRequest()
    req.addCertificateType(CertificateRequest.ClientCertificateType.DSS_FIXED_DH)
    assertFalse(req.isSupportedKeyType(key))
  }
}
