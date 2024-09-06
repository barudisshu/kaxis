/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.auth

import io.kaxis.JceProvider
import io.kaxis.dtls.TestCertificatesTools.*
import io.kaxis.util.SslContextUtil
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test

/**
 * Verifies behavior of [X509CertPath], which is **.jks** format.
 */
internal class X509CertPathIdentityTest {
  companion object {
    val ALIAS_CLIENT = "client"

    private lateinit var ecCredentials: SslContextUtil.Credentials
    private lateinit var ed25519Credentials: SslContextUtil.Credentials

    @BeforeAll
    @JvmStatic
    fun init() {
      assertDoesNotThrow {
        ecCredentials =
          SslContextUtil.loadCredentials(
            KEY_STORE_URI,
            ALIAS_CLIENT,
            KEY_STORE_PASSWORD,
            KEY_STORE_PASSWORD,
          )
        if (JceProvider.isSupported(
            JceProvider.ED25519,
          ) && SslContextUtil.isAvailableFromUri(EDDSA_KEY_STORE_URI)
        ) {
          ed25519Credentials =
            SslContextUtil.loadCredentials(
              EDDSA_KEY_STORE_URI,
              "clienteddsa",
              KEY_STORE_PASSWORD,
              KEY_STORE_PASSWORD,
            )
        }
      }
    }
  }

  @Test
  fun testGetNameReturnsNamedInterfaceUri() {
    val id = X509CertPath.fromCertificateChain(ecCredentials.certificateChainAsList)
    assertEquals(ecCredentials.certificateChain[0].subjectX500Principal.name, id.name)
  }

  @Test
  fun testGetCNReturnsCN() {
    val id = X509CertPath.fromCertificateChain(ecCredentials.certificateChainAsList)
    assertEquals("cf-client", id.getCN())
  }

  @Test
  fun testGetTargetReturnsFirstCertificate() {
    val id = X509CertPath.fromCertificateChain(ecCredentials.certificateChainAsList)
    assertEquals(ecCredentials.certificateChain[0], id.target)
  }

  @Test
  fun testConstructorCreatesEcChainFromBytes() {
    val id = X509CertPath.fromCertificateChain(ecCredentials.certificateChainAsList)
    // GIVEN a SubjectPublicKeyInfo object
    val chain = id.toByteArray()

    // WHEN creating a RawPublicKeyIdentity from it
    val principal = X509CertPath.fromBytes(chain)

    // THEN the principal is the same
    assertEquals(principal, id)
    assertEquals(principal.path, id.path)
    assertSigning("X509", ecCredentials.privateKey, principal.target.publicKey, "SHA256withECDSA")
  }

  @Test
  fun testConstructorCreatesEd25519ChainFromBytes() {
    val id = X509CertPath.fromCertificateChain(ed25519Credentials.certificateChainAsList)
    // GIVEN a SubjectPublicKeyInfo object
    val chain = id.toByteArray()

    // WHEN creating a RawPublicKeyIdentity from it
    val principal = X509CertPath.fromBytes(chain)

    // THEN the principal is the same
    assertEquals(principal, id)
    assertEquals(principal.path, id.path)
    assertSigning("X509", ed25519Credentials.privateKey, principal.target.publicKey, "ED25519")
  }
}
