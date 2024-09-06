/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
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
