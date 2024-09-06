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
import io.kaxis.dtls.TestCertificatesTools.assertSigning
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException

/**
 * Verifies behavior of [RawPublicKeyIdentity]
 */
internal class RawPublicKeyIdentityTest {
  companion object {
    private const val URI_PREFIX = "ni:///sha-256;"

    private lateinit var ecKeyPair: KeyPair
    private lateinit var ed25519KeyPair: KeyPair
    private lateinit var ed448KeyPair: KeyPair

    @JvmStatic
    @BeforeAll
    fun init() {
      JceProvider.init()

      try {
        val generator = KeyPairGenerator.getInstance("EC")
        ecKeyPair = generator.generateKeyPair()
      } catch (e: NoSuchAlgorithmException) {
        // IGNORED
      }

      try {
        val generator = KeyPairGenerator.getInstance(JceProvider.OID_ED25519)
        ed25519KeyPair = generator.generateKeyPair()
      } catch (e: NoSuchAlgorithmException) {
        // IGNORED
      }

      try {
        val generator = KeyPairGenerator.getInstance(JceProvider.OID_ED448)
        ed448KeyPair = generator.generateKeyPair()
      } catch (e: NoSuchAlgorithmException) {
        // IGNORED
      }
    }
  }

  @Test
  fun testGetNameReturnsNamedInterfaceUri() {
    val id = RawPublicKeyIdentity(ecKeyPair.public)
    assertThatNameIsValidNamedInterfaceUri(id.name)
  }

  @Test
  fun testGetSubjectInfoReturnsEncodedKey() {
    val id = RawPublicKeyIdentity(ecKeyPair.public)
    assertArrayEquals(id.key.encoded, id.subjectInfo)
  }

  @Test
  fun testConstructorCreatesEcPublicKeyFromSubjectInfo() {
    // GIVEN a SubjectPublicKeyInfo object
    val subjectInfo = ecKeyPair.public.encoded

    // WHEN creating a RawPublicKeyIdentity from it
    var principal = RawPublicKeyIdentity(subjectInfo = subjectInfo, keyAlgorithm = ecKeyPair.public.algorithm)

    // THEN the principal contains the public key corresponding to the subject info
    assertEquals(ecKeyPair.public, principal.key)

    // WHEN creating a RawPublicKeyIdentity from it
    principal = RawPublicKeyIdentity(subjectInfo)

    // THEN the principal contains the public key corresponding to the subject info
    assertEquals(ecKeyPair.public, principal.key)

    assertSigning("RPK", ecKeyPair.private, principal.key, "SHA256withECDSA")
  }

  @Test
  fun testConstructorCreatesEd25519PublicKeyFromSubjectInfo() {
    // GIVEN a SubjectPublicKeyInfo object
    val subjectInfo = ed25519KeyPair.public.encoded

    // WHEN creating a RawPublicKeyIdentity from it
    var principal = RawPublicKeyIdentity(subjectInfo, ed25519KeyPair.public.algorithm)

    // THEN the principal contains the public key corresponding to the subject info
    assertEquals(ed25519KeyPair.public, principal.key)

    // WHEN creating a RawPublicKeyIdentity from it
    principal = RawPublicKeyIdentity(subjectInfo)

    // THEN the principal contains the public key corresponding to the subject info
    assertEquals(ed25519KeyPair.public, principal.key)
    assertSigning("PRK", ed25519KeyPair.private, principal.key, "ED25519")
  }

  @Test
  fun testConstructorCreatesEd448PublicKeyFromSubjectInfo() {
    // GIVEN a SubjectPublicKeyInfo object
    val subjectInfo = ed448KeyPair.public.encoded

    // WHEN creating a RawPublicKeyIdentity from it
    var principal = RawPublicKeyIdentity(subjectInfo, ed448KeyPair.public.algorithm)

    // THEN the principal contains the public key corresponding to the subject info
    assertEquals(ed448KeyPair.public, principal.key)

    // WHEN creating a RawPublicKeyIdentity from it
    principal = RawPublicKeyIdentity(subjectInfo)

    // THEN the principal contains the public key corresponding to the subject info
    assertEquals(ed448KeyPair.public, principal.key)
    assertSigning("PRK", ed448KeyPair.private, principal.key, "ED448")
  }

  private fun assertThatNameIsValidNamedInterfaceUri(name: String) {
    assertTrue(name.startsWith(URI_PREFIX))
    val hash = name.substring(URI_PREFIX.length)
    assertFalse(hash.endsWith("="))
    assertFalse(hash.endsWith("+"))
    assertFalse(hash.endsWith("/"))
    assertFalse(hash.endsWith("\n"))
    assertFalse(hash.endsWith("\t"))
  }
}
