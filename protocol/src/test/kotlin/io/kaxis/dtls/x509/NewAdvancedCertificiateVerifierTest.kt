/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.x509

import io.kaxis.dtls.DtlsTestTools
import io.kaxis.dtls.x509.verifier.StaticNewAdvancedCertificateVerifier
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

internal class NewAdvancedCertificiateVerifierTest {
  companion object {
    private lateinit var trusts: Array<X509Certificate>
    private lateinit var issuers: MutableSet<X500Principal>

    @JvmStatic
    @BeforeAll
    fun setUp() {
      trusts = DtlsTestTools.getTrustedCertificates()
      issuers = mutableSetOf()
      trusts.forEach { trust ->
        issuers.add(trust.subjectX500Principal)
      }
      assertFalse(issuers.isEmpty())
    }
  }

  @Test
  fun testUseEmptyAcceptedIssuers() {
    val certificateVerifier =
      StaticNewAdvancedCertificateVerifier
        .builder()
        .setTrustedCertificates(trusts).setUseEmptyAcceptedIssuers(true).build()
    assertTrue(certificateVerifier.acceptedIssuers.isEmpty())
  }

  @Test
  fun testAcceptedIssuers() {
    val certificateVerifier = StaticNewAdvancedCertificateVerifier.builder().setTrustedCertificates(trusts).build()
    assertEquals(issuers.size, certificateVerifier.acceptedIssuers.size)
  }
}
