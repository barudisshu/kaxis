/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.x509

import io.kaxis.dtls.CertificateType
import io.kaxis.dtls.DtlsTestTools
import io.kaxis.dtls.SignatureAndHashAlgorithm
import io.kaxis.dtls.TestCertificatesTools
import io.kaxis.dtls.cipher.XECDHECryptography
import io.kaxis.dtls.x509.provider.KeyManagerCertificateProvider
import io.kaxis.util.Utility
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.spec.*
import kotlin.test.assertContains

internal class CertificateConfigurationHelperTest {
  private lateinit var helper: CertificateConfigurationHelper

  @BeforeEach
  fun setUp() {
    helper = CertificateConfigurationHelper()
  }

  @Test
  fun testRawPublicKeySetupSupportsClientAndServer() {
    helper.addConfigurationDefaultsForTrusts(DtlsTestTools.getClientPublicKey())
    assertTrue(helper.canBeusedForAuthentication(true))
    assertTrue(helper.canBeusedForAuthentication(false))
    val defaultSupportedGroups = helper.defaultSupportedGroups
    assertEquals(1, defaultSupportedGroups.size)
    assertContains(defaultSupportedGroups, XECDHECryptography.SupportedGroup.secp256r1)
    val defaultSignatureAndHashAlgorithms = helper.defaultSignatureAndHashAlgorithms
    assertEquals(1, defaultSignatureAndHashAlgorithms.size)
    assertContains(defaultSignatureAndHashAlgorithms, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
  }

  @Test
  fun testRawRsaPublicKeySetupSupportsClientAndServer() {
    helper.addConfigurationDefaultsFor(DtlsTestTools.getClientRsaPublicKey())
    assertTrue(helper.canBeusedForAuthentication(true))
    assertTrue(helper.canBeusedForAuthentication(false))
    val defaultSupportedGroups = helper.defaultSupportedGroups
    assertEquals(0, defaultSupportedGroups.size)
    val defaultSignatureAndHashAlgorithms = helper.defaultSignatureAndHashAlgorithms
    assertEquals(1, defaultSignatureAndHashAlgorithms.size)
    assertContains(defaultSignatureAndHashAlgorithms, SignatureAndHashAlgorithm.SHA256_WITH_RSA)
  }

  @Test
  fun testCertificateChainWithClientUsageSupportsClientOnly() {
    val credentials = DtlsTestTools.getCredentials("clientext")
    helper.addConfigurationDefaultsFor(credentials.certificateChainAsList)
    assertTrue(helper.canBeusedForAuthentication(true))
    assertFalse(helper.canBeusedForAuthentication(false))
    val defaultSupportedGroups = helper.defaultSupportedGroups
    assertEquals(1, defaultSupportedGroups.size)
    assertContains(defaultSupportedGroups, XECDHECryptography.SupportedGroup.secp256r1)
    val defaultSignatureAndHashAlgorithms = helper.defaultSignatureAndHashAlgorithms
    assertEquals(2, defaultSignatureAndHashAlgorithms.size)
    assertContains(defaultSignatureAndHashAlgorithms, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
  }

  @Test
  fun testCertificateRsaChain() {
    val credentials = DtlsTestTools.getCredentials("serverrsa")
    helper.addConfigurationDefaultsFor(credentials.certificateChainAsList)
    // no key usage extension
    assertTrue(helper.canBeusedForAuthentication(true))
    assertTrue(helper.canBeusedForAuthentication(false))
    val defaultSupportedGroups = helper.defaultSupportedGroups
    assertEquals(1, defaultSupportedGroups.size)
    assertContains(defaultSupportedGroups, XECDHECryptography.SupportedGroup.secp256r1)
    val defaultSignatureAndHashAlgorithms = helper.defaultSignatureAndHashAlgorithms
    assertEquals(2, defaultSignatureAndHashAlgorithms.size)
    assertContains(defaultSignatureAndHashAlgorithms, SignatureAndHashAlgorithm.SHA256_WITH_RSA)
    assertContains(defaultSignatureAndHashAlgorithms, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
  }

  @Test
  fun testRsaCertificateChainWithoutKeyUsageSupportsClientAndServer() {
    helper.addConfigurationDefaultsFor(DtlsTestTools.getServerCaRsaCertificateChainAsList())
    assertTrue(helper.canBeusedForAuthentication(true))
    assertTrue(helper.canBeusedForAuthentication(false))
    val defaultSupportedGroups = helper.defaultSupportedGroups
    assertEquals(1, defaultSupportedGroups.size)
    assertContains(defaultSupportedGroups, XECDHECryptography.SupportedGroup.secp256r1)
    val defaultSignatureAndHashAlgorithms = helper.defaultSignatureAndHashAlgorithms
    assertEquals(2, defaultSignatureAndHashAlgorithms.size)
    assertContains(defaultSignatureAndHashAlgorithms, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
    assertContains(defaultSignatureAndHashAlgorithms, SignatureAndHashAlgorithm.SHA256_WITH_RSA)
  }

  @Test
  fun testTrustedCertificatesSupportsClientAndServer() {
    val credentials = DtlsTestTools.getCredentials("clientext")
    helper.addConfigurationDefaultsForTrusts(credentials.certificateChain)
    assertTrue(helper.canBeusedForAuthentication(true))
    assertTrue(helper.canBeusedForAuthentication(false))
    val defaultSupportedGroups = helper.defaultSupportedGroups
    assertEquals(1, defaultSupportedGroups.size)
    assertContains(defaultSupportedGroups, XECDHECryptography.SupportedGroup.secp256r1)
    val defaultSignatureAndHashAlgorithms = helper.defaultSignatureAndHashAlgorithms
    assertEquals(1, defaultSignatureAndHashAlgorithms.size)
    assertContains(defaultSignatureAndHashAlgorithms, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
  }

  @Test
  fun testTrustedRsaCertificatesSupportsClientAndServer() {
    helper.addConfigurationDefaultsForTrusts(DtlsTestTools.getServerCaRsaCertificateChain())
    assertTrue(helper.canBeusedForAuthentication(true))
    assertTrue(helper.canBeusedForAuthentication(false))
    val defaultSupportedGroups = helper.defaultSupportedGroups
    assertEquals(1, defaultSupportedGroups.size)
    assertContains(defaultSupportedGroups, XECDHECryptography.SupportedGroup.secp256r1)
    val defaultSignatureAndHashAlgorithms = helper.defaultSignatureAndHashAlgorithms
    assertEquals(2, defaultSignatureAndHashAlgorithms.size)
    assertContains(defaultSignatureAndHashAlgorithms, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
    assertContains(defaultSignatureAndHashAlgorithms, SignatureAndHashAlgorithm.SHA256_WITH_RSA)
  }

  @Test
  fun testWithKeyManager() {
    val keyManager = DtlsTestTools.getServerKeyManager()
    val provider = KeyManagerCertificateProvider(keyManager, mutableListOf(CertificateType.X_509))
    provider.setupConfigurationHelper(helper)
    // no key usage extension
    assertTrue(helper.canBeusedForAuthentication(true))
    assertTrue(helper.canBeusedForAuthentication(false))
    val defaultSupportedGroups = helper.defaultSupportedGroups
    assertEquals(1, defaultSupportedGroups.size)
    assertContains(defaultSupportedGroups, XECDHECryptography.SupportedGroup.secp256r1)
    val defaultSignatureAndHashAlgorithms = helper.defaultSignatureAndHashAlgorithms
    assertEquals(2, defaultSignatureAndHashAlgorithms.size)
    assertContains(defaultSignatureAndHashAlgorithms, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
    assertContains(defaultSignatureAndHashAlgorithms, SignatureAndHashAlgorithm.SHA256_WITH_RSA)
  }

  @Test
  fun testWithEdDsaKeyManager() {
    val edDsaKeyManager = DtlsTestTools.getServerEdDsaKeyManager()
    assertNotNull(edDsaKeyManager)
    val provider = KeyManagerCertificateProvider(edDsaKeyManager, mutableListOf(CertificateType.X_509))
    provider.setupConfigurationHelper(helper)
    // no key usage extension
    assertTrue(helper.canBeusedForAuthentication(true))
    assertTrue(helper.canBeusedForAuthentication(false))
    val defaultSupportedGroups = helper.defaultSupportedGroups
    assertEquals(2, defaultSupportedGroups.size)
    assertContains(defaultSupportedGroups, XECDHECryptography.SupportedGroup.X25519)
    assertContains(defaultSupportedGroups, XECDHECryptography.SupportedGroup.secp256r1)
    val defaultSignatureAndHashAlgorithms = helper.defaultSignatureAndHashAlgorithms
    assertEquals(3, defaultSignatureAndHashAlgorithms.size)
    assertContains(defaultSignatureAndHashAlgorithms, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
    assertContains(defaultSignatureAndHashAlgorithms, SignatureAndHashAlgorithm.SHA256_WITH_RSA)
    assertContains(defaultSignatureAndHashAlgorithms, SignatureAndHashAlgorithm.INTRINSIC_WITH_ED25519)
  }

  @Test
  fun testWithKeyManagerEcdsaOnly() {
    val keyManager = DtlsTestTools.getKeyManager(TestCertificatesTools.serverCredentials)
    val provider = KeyManagerCertificateProvider(keyManager, mutableListOf(CertificateType.X_509))
    provider.setupConfigurationHelper(helper)
    // no key usage extension
    assertTrue(helper.canBeusedForAuthentication(true))
    assertTrue(helper.canBeusedForAuthentication(false))
    val defaultSupportedGroups = helper.defaultSupportedGroups
    assertEquals(1, defaultSupportedGroups.size)
    assertContains(defaultSupportedGroups, XECDHECryptography.SupportedGroup.secp256r1)
    val defaultSignatureAndHashAlgorithms = helper.defaultSignatureAndHashAlgorithms
    assertEquals(1, defaultSignatureAndHashAlgorithms.size)
    assertContains(defaultSignatureAndHashAlgorithms, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
  }

  @Test
  fun testWithKeyManagerRsaOnly() {
    val keyManager = DtlsTestTools.getKeyManager(TestCertificatesTools.serverRsaCredentials)
    val provider = KeyManagerCertificateProvider(keyManager, mutableListOf(CertificateType.X_509))
    provider.setupConfigurationHelper(helper)
    // no key usage extension
    assertTrue(helper.canBeusedForAuthentication(true))
    assertTrue(helper.canBeusedForAuthentication(false))
    val defaultSupportedGroups = helper.defaultSupportedGroups
    assertEquals(1, defaultSupportedGroups.size)
    assertContains(defaultSupportedGroups, XECDHECryptography.SupportedGroup.secp256r1)
    val defaultSignatureAndHashAlgorithms = helper.defaultSignatureAndHashAlgorithms
    assertEquals(2, defaultSignatureAndHashAlgorithms.size)
    assertContains(defaultSignatureAndHashAlgorithms, SignatureAndHashAlgorithm.SHA256_WITH_RSA)
    assertContains(defaultSignatureAndHashAlgorithms, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
  }

  @Test
  fun testWithKeyManagerRsaRawPublicKeyOnly() {
    val keyManager = DtlsTestTools.getKeyManager(TestCertificatesTools.serverRsaCredentials)
    val provider = KeyManagerCertificateProvider(keyManager, mutableListOf(CertificateType.RAW_PUBLIC_KEY))
    provider.setupConfigurationHelper(helper)
    // no key usage extension
    assertTrue(helper.canBeusedForAuthentication(true))
    assertTrue(helper.canBeusedForAuthentication(false))
    val defaultSupportedGroups = helper.defaultSupportedGroups
    assertEquals(0, defaultSupportedGroups.size)
    val defaultSignatureAndHashAlgorithms = helper.defaultSignatureAndHashAlgorithms
    assertEquals(1, defaultSignatureAndHashAlgorithms.size)
    assertContains(defaultSignatureAndHashAlgorithms, SignatureAndHashAlgorithm.SHA256_WITH_RSA)
  }

  /**
   * The test verifies, that the demo ECDSA keys of Leshan could be verified. Since Java 15 the public keys
   * must ensure, thaht the passed in value is a positive number. Otherwise the key may not be applicable for
   * signature verification. The key are copied from [LeshanBootstrapServerBuilderTest](https://github.com/eclipse-leshan/leshan/blob/master/leshan-server-cf/src/test/java/org/eclipse/leshan/server/californium/bootstrap/LeshanBootstrapServerBuilderTest.java#L61-L85)
   */
  @Test
  fun testWithLeshanDemoRPK() {
    // Get point values
    val publicX = Utility.hex2ByteArray("89c048261979208666f2bfb188be1968fc9021c416ce12828c06f4e314c167b5")
    val publicY = Utility.hex2ByteArray("cbf1eb7587f08e01688d9ada4be859137ca49f79394bad9179326b3090967b68")
    val privateS = Utility.hex2ByteArray("e67b68d2aaeb6550f19d98cade3ad62b39532e02e6b422e1f7ea189dabaea5d2")

    // Get Elliptic Curve Parameter spec for secp256r1
    val algoParameters = AlgorithmParameters.getInstance("EC")
    algoParameters.init(ECGenParameterSpec("secp256r1"))
    val parameterSpec = algoParameters.getParameterSpec(ECParameterSpec::class.java)

    // Create key spec
    val publicKeySpec = ECPublicKeySpec(ECPoint(BigInteger(1, publicX), BigInteger(1, publicY)), parameterSpec)
    val privateKeySpec = ECPrivateKeySpec(BigInteger(1, privateS), parameterSpec)

    // Get keys
    val publicKey = KeyFactory.getInstance("EC").generatePublic(publicKeySpec)
    val privateKey = KeyFactory.getInstance("EC").generatePrivate(privateKeySpec)
    helper.verifyKeyPair(privateKey, publicKey)
  }
}
