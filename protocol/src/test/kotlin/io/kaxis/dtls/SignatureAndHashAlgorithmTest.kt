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

import io.kaxis.dtls.cipher.ThreadLocalKeyPairGenerator
import io.kaxis.dtls.cipher.ThreadLocalSignature
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.GeneralSecurityException
import java.security.KeyPair
import java.security.Signature
import kotlin.test.*

internal class SignatureAndHashAlgorithmTest {
  companion object {
    private var ecdsa: KeyPair? = null
    private var eddsa25519: KeyPair? = null
    private var eddsa448: KeyPair? = null
    private lateinit var data: ByteArray

    @JvmStatic
    @BeforeAll
    fun setUp() {
      data = ByteArray(128)
      for (index in data.indices) {
        data[index] = index.toByte()
      }
      ecdsa = TestCertificatesTools.getServerKeyPair()
      try {
        val kpg = ThreadLocalKeyPairGenerator("Ed25519").currentWithCause()
        if (kpg != null) {
          eddsa25519 = kpg.generateKeyPair()
        }
      } catch (e: GeneralSecurityException) {
        // NOSONAR
      }
      try {
        val kpg = ThreadLocalKeyPairGenerator("Ed448").currentWithCause()
        if (kpg != null) {
          eddsa448 = kpg.generateKeyPair()
        }
      } catch (e: GeneralSecurityException) {
        // NOSONAR
      }
    }
  }

  @Test
  fun testEd25519Signature() {
    assumeTrue(eddsa25519 != null, "Ed25519 not supported!")
    val signature = ThreadLocalSignature("Ed25519").currentWithCause()
    signAndVerify(signature!!, eddsa25519!!)
  }

  @Test
  fun testEd448Signature() {
    assumeTrue(eddsa448 != null, "Ed448 not supported!")
    val signature = ThreadLocalSignature("Ed448").currentWithCause()
    signAndVerify(signature!!, eddsa448!!)
  }

  @Test
  fun `testSignatureAndHashs()`() {
    var count = 0
    var countEcdsa = 0
    var countEddsa = 0
    SignatureAndHashAlgorithm.HashAlgorithm.entries.forEach { hashAlgorithm ->
      SignatureAndHashAlgorithm.SignatureAlgorithm.entries.forEach { signatureAlgorithm ->
        val signAndHash = SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm)
        val signature = signAndHash.getThreadLocalSignature().current()
        if (signature != null) {
          assertTrue { signAndHash.isSupported }
          ++count
          if (signatureAlgorithm == SignatureAndHashAlgorithm.SignatureAlgorithm.ECDSA) {
            ++countEcdsa
            signAndVerify(signature, ecdsa!!)
          } else if (signatureAlgorithm == SignatureAndHashAlgorithm.SignatureAlgorithm.ED25519) {
            ++countEddsa
            signAndVerify(signature, eddsa25519!!)
          } else if (signatureAlgorithm == SignatureAndHashAlgorithm.SignatureAlgorithm.ED448) {
            ++countEddsa
            signAndVerify(signature, eddsa448!!)
          }
        } else {
          assertFalse { signAndHash.isSupported }
        }
      }
    }
    assertTrue(count > 0, "no signatures available!")
    assumeTrue(countEcdsa > 0, "no ECDSA signatures available!")
    println("Signature: $count overall, $countEcdsa ECDSA, $countEddsa EdDSA.")
  }

  @Test
  fun testUnknownSignatureAndHashAlgorithm() {
    val algo = SignatureAndHashAlgorithm(80, 64)
    assertEquals(algo.toString(), "0x50with0x40")
    assertNull(algo.jcaName)
    assertNotEquals(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA, algo)
  }

  @Test
  fun testUnknownSignatureAndHashAlgorithmCauseException() {
    val algo = SignatureAndHashAlgorithm(80, 64)
    assertThrows<GeneralSecurityException> { algo.getThreadLocalSignature().currentWithCause() }
  }

  @Test
  fun testValueOf() {
    val algorithm = SignatureAndHashAlgorithm.valueOf("SHA384withRSA")
    assertNotNull(algorithm)
    assertEquals(SignatureAndHashAlgorithm.HashAlgorithm.SHA384, algorithm.hash)
    assertEquals(SignatureAndHashAlgorithm.SignatureAlgorithm.RSA, algorithm.signature)
  }

  @Test
  fun testValueOfEd25519() {
    assumeTrue(eddsa25519 != null, "Ed25519 not supported!")
    var algorithm = SignatureAndHashAlgorithm.valueOf("Ed25519")
    assertNotNull(algorithm)
    assertEquals(SignatureAndHashAlgorithm.HashAlgorithm.INTRINSIC, algorithm.hash)
    assertEquals(SignatureAndHashAlgorithm.SignatureAlgorithm.ED25519, algorithm.signature)

    algorithm = SignatureAndHashAlgorithm.valueOf("ED25519")
    assertEquals(SignatureAndHashAlgorithm.HashAlgorithm.INTRINSIC, algorithm.hash)
    assertEquals(SignatureAndHashAlgorithm.SignatureAlgorithm.ED25519, algorithm.signature)
  }

  @Test
  fun testValueOfEd448() {
    assumeTrue(eddsa448 != null, "Ed448 not supported!")
    var algorithm = SignatureAndHashAlgorithm.valueOf("Ed448")
    assertNotNull(algorithm)
    assertEquals(SignatureAndHashAlgorithm.HashAlgorithm.INTRINSIC, algorithm.hash)
    assertEquals(SignatureAndHashAlgorithm.SignatureAlgorithm.ED448, algorithm.signature)

    algorithm = SignatureAndHashAlgorithm.valueOf("ED448")
    assertEquals(SignatureAndHashAlgorithm.HashAlgorithm.INTRINSIC, algorithm.hash)
    assertEquals(SignatureAndHashAlgorithm.SignatureAlgorithm.ED448, algorithm.signature)
  }

  @Test
  fun testGetSignatureAlgorithm() {
    val algorithms =
      SignatureAndHashAlgorithm.getSignatureAlgorithms(
        TestCertificatesTools.getServerCaRsaCertificateChainAsList(),
      )
    assertEquals(2, algorithms.size)
    assertContains(algorithms, SignatureAndHashAlgorithm.SHA256_WITH_RSA)
    assertContains(algorithms, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
  }

  @Test
  fun testEnsureSignatureAlgorithm() {
    val algorithms = arrayListOf<SignatureAndHashAlgorithm>()
    SignatureAndHashAlgorithm.ensureSignatureAlgorithm(algorithms, TestCertificatesTools.getPublicKey())
    assertEquals(1, algorithms.size)
    assertContains(algorithms, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
    SignatureAndHashAlgorithm.ensureSignatureAlgorithm(
      algorithms,
      TestCertificatesTools.getServerCaRsaCertificateChain()[1].publicKey,
    )
    assertEquals(2, algorithms.size)
    assertContains(algorithms, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
    assertContains(algorithms, SignatureAndHashAlgorithm.SHA256_WITH_RSA)
  }

  @Test
  fun testEnsureSignatureAlgorithmForEdDsa() {
    assumeTrue(SignatureAndHashAlgorithm.INTRINSIC_WITH_ED25519.isSupported, "ED25519 requires JCE support!")
    val credentials = TestCertificatesTools.getCredentials("clienteddsa")
    assertNotNull(credentials, "clienteddsa credentials missing")
    val algorithms = arrayListOf<SignatureAndHashAlgorithm>()
    SignatureAndHashAlgorithm.ensureSignatureAlgorithm(algorithms, credentials.publicKey)
    assertEquals(1, algorithms.size)
    assertContains(algorithms, SignatureAndHashAlgorithm.INTRINSIC_WITH_ED25519)
  }

  private fun signAndVerify(
    signature: Signature,
    pair: KeyPair,
  ) {
    TestCertificatesTools.assertSigning("", pair.private, pair.public, signature)
  }
}
