/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.extension.generator

import io.kaxis.*
import io.kaxis.ansi.Highlight
import io.kaxis.extension.param.SigAlgEnum
import io.mockk.junit5.MockKExtension
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.operator.OperatorCreationException
import org.junit.jupiter.api.*
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.extension.ExtendWith
import org.junit.jupiter.api.io.TempDir
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.io.File
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.time.OffsetDateTime
import kotlin.test.assertEquals

@ExtendWith(MockKExtension::class)
@TestMethodOrder(MethodOrderer.DisplayName::class)
internal class KaxisBcFabricTest {
  companion object {
    @JvmStatic
    fun getData(): List<Arguments> {
      return listOf(
        Arguments.of(RSA, SigAlgEnum.SHA_256_WITH_RSA, NISTObjectIdentifiers.id_aes128_CBC),
        Arguments.of(RSA, SigAlgEnum.SHA_256_WITH_RSA_AND_MGF1, PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC),
        Arguments.of(RSA, SigAlgEnum.SHA_384_WITH_RSA_AND_MGF1, NISTObjectIdentifiers.id_aes256_CBC),
        Arguments.of(DSA, SigAlgEnum.SHA_224_WITH_DSA, NISTObjectIdentifiers.id_aes256_CBC),
        Arguments.of(ECDSA, SigAlgEnum.SHA_1_WITH_ECDSA, NISTObjectIdentifiers.id_aes192_CBC),
      )
    }
  }

  @Test
  @DisplayName("01 - Timeslot")
  fun timeSlotTest() {
    var timeSlot = KaxisBcFabric.generateTimeSlot(1)
    assertNotNull(timeSlot)
    assertTrue { timeSlot.offsetEndDate.isAfter(timeSlot.offsetStartDate) }
    assertTrue { timeSlot.endDate.after(timeSlot.startDate) }
    timeSlot = KaxisBcFabric.generateTimeSlot(-1)
    assertNotNull(timeSlot)
    assertTrue { timeSlot.offsetEndDate.isAfter(timeSlot.offsetStartDate) }
    assertTrue { timeSlot.offsetEndDate.isAfter(OffsetDateTime.now()) }
    assertTrue { timeSlot.offsetStartDate.isBefore(OffsetDateTime.now()) }
    // expired right now
    timeSlot = KaxisBcFabric.generateTimeSlot(0)
    assertTrue { timeSlot.offsetEndDate.isAfter(timeSlot.offsetStartDate) }
    assertTrue { timeSlot.offsetStartDate.isBefore(OffsetDateTime.now()) }
  }

  @Test
  @DisplayName("02 - JcaKeyPair.CA")
  fun generateX509CaChainTest(
    @TempDir tempDir: File,
  ) {
    val timeSlot = KaxisBcFabric.generateTimeSlot(1)
    val keyPairGenerator = KeyPairGenerator.getInstance(RSA, BCProvider.PROVIDER_NAME)
    // atLeast 1024
    keyPairGenerator.initialize(1024)
    val rootKeyPair = keyPairGenerator.generateKeyPair()

    val rootCertIssuer = X500Name("CN=China")
    val jcaKeyPair = KaxisBcFabric.generateX509CaChain(rootKeyPair, timeSlot, rootCertIssuer, "SHA1withRSA")

    assertNotNull(jcaKeyPair)

    val aPublic = jcaKeyPair.publicKey
    val aPrivate = jcaKeyPair.privateKey
    val x509Certificate = jcaKeyPair.x509Certificate

    assertEquals(aPublic, x509Certificate.asPublicKey())
    assertTrue { x509Certificate.isCa() }

    val caFile = File(tempDir, "ca.crt")
    val keyFile = File(tempDir, "ca.key")
    val pkcs8File = File(tempDir, "pkcs8.key")

    KaxisBcFabric.exportX509ToFileBase64Encoded(x509Certificate, caFile)
    val caPemObjects = caFile.asPemObjects()
    assertEquals("CERTIFICATE", caPemObjects[0].type)
    val caFileContent = Files.readString(caFile.toPath())
    print(Highlight.GREEN_BOLD)
    println(caFileContent)
    print(Highlight.RESET)

    assertThrows<OperatorCreationException> {
      KaxisBcFabric.exportKeyPairToFile(
        aPrivate,
        keyFile,
        pkcs8File,
        GNUObjectIdentifiers.Serpent_128_ECB,
        null,
      )
    }
    KaxisBcFabric.exportKeyPairToFile(aPrivate, keyFile, pkcs8File, NISTObjectIdentifiers.id_aes256_CBC, null)

    // RSA
    val keyPemObjects = keyFile.asPemObjects()
    assertEquals("RSA PRIVATE KEY", keyPemObjects[0].type)
    val keyFileContent = Files.readString(keyFile.toPath())
    print(Highlight.YELLOW_BOLD)
    println(keyFileContent)
    print(Highlight.RESET)

    // PKCS#8
    val pkcs8PemObjects = pkcs8File.asPemObjects()
    assertEquals("PRIVATE KEY", pkcs8PemObjects[0].type)
    val pkcs8FileContent = Files.readString(pkcs8File.toPath())
    print(Highlight.BLUE)
    println(pkcs8FileContent)
    print(Highlight.RESET)

    val certificates = caFile.asX509s()
    assertEquals(x509Certificate, certificates[0])

    val keyEncryptedFile = File(tempDir, "ca-e.key")
    val pkcs8EncryptedFile = File(tempDir, "pkcs8-e.key")
    KaxisBcFabric.exportKeyPairToFile(
      aPrivate,
      keyEncryptedFile,
      pkcs8EncryptedFile,
      NISTObjectIdentifiers.id_aes128_CBC,
      "P@ssw0rd",
    )
    val pkcs8EncryptedPemObjects = pkcs8EncryptedFile.asPemObjects()
    assertEquals("ENCRYPTED PRIVATE KEY", pkcs8EncryptedPemObjects[0].type)

    val keyEncryptedUnFile = File(tempDir, "ca-u.key")
    val pkcs8EncryptedUnFile = File(tempDir, "pkcs8-u.key")
    assertThrows<OperatorCreationException> {
      KaxisBcFabric.exportKeyPairToFile(
        aPrivate,
        keyEncryptedUnFile,
        pkcs8EncryptedUnFile,
        NISTObjectIdentifiers.id_aes128_CFB,
        "P@ssw0rd",
      )
    }
  }

  @TempDir
  lateinit var tempDir: File

  @DisplayName("03 - JcaKeyPair.Algorithm")
  @ParameterizedTest(name = "0{index}: algorithm: ''{0}'', signature algorithm: ''{1}'', asn1: ''{2}''")
  @MethodSource("getData")
  fun generateX509CertificateAndKeyTest(
    algorithm: String,
    signatureAlgorithm: SigAlgEnum,
    keyEncryptionAlg: ASN1ObjectIdentifier,
  ) {
    val timeSlot = KaxisBcFabric.generateTimeSlot(1)
    val rootKeyPair = KeyPairGenerator.getInstance(algorithm, BCProvider.PROVIDER_NAME).generateKeyPair()
    val rootCertIssuer = X500Name("CN=china")
    val rootJcaKeyPair =
      KaxisBcFabric.generateX509CaChain(rootKeyPair, timeSlot, rootCertIssuer, signatureAlgorithm.signatureAlgorithm)

    val issuedCertKeyPair = KeyPairGenerator.getInstance(algorithm, BCProvider.PROVIDER_NAME).generateKeyPair()
    val rootCert = rootJcaKeyPair.x509Certificate

    val issuedCertSubject = X500Name("CN=China")
    val dNsName = "io.kaxis"
    val iPaddress = "10.0.0.1"
    val jcaKeyPair =
      KaxisBcFabric.generateX509CertificateAndKey(
        rootKeyPair,
        issuedCertKeyPair,
        rootCert,
        rootCertIssuer,
        issuedCertSubject,
        timeSlot,
        dNsName,
        iPaddress,
        signatureAlgorithm.signatureAlgorithm,
      )

    assertNotNull(jcaKeyPair)
    val aPublic = jcaKeyPair.publicKey
    val aPrivate = jcaKeyPair.privateKey
    val x509Certificate = jcaKeyPair.x509Certificate

    assertEquals(aPublic, x509Certificate.asPublicKey())

    val caFile = File(tempDir, "server.crt")
    val keyFile = File(tempDir, "server.key")
    val keyEncryptedFile = File(tempDir, "serverEncrypted.key")
    val pkcs8File = File(tempDir, "pkcs8.key")
    val pkcs8EncryptedFile = File(tempDir, "pkcs8Encrypted.key")

    KaxisBcFabric.exportX509ToFileBase64Encoded(x509Certificate, caFile)
    val caPemObjects = caFile.asPemObjects()
    assertEquals("CERTIFICATE", caPemObjects[0].type)
    val caFileContent = Files.readString(caFile.toPath())
    print(Highlight.GREEN_BOLD)
    println(caFileContent)
    print(Highlight.RESET)

    // Without password
    KaxisBcFabric.exportKeyPairToFile(aPrivate, keyFile, pkcs8File, keyEncryptionAlg, null)

    // algorithm
    val keyPemObjects = keyFile.asPemObjects()
    assertEquals("$algorithm PRIVATE KEY", keyPemObjects[0].type)
    val keyFileContent = Files.readString(keyFile.toPath())
    print(Highlight.YELLOW_BOLD)
    println(keyFileContent)
    print(Highlight.RESET)

    val pkcs8PemObjects = pkcs8File.asPemObjects()
    assertEquals("PRIVATE KEY", pkcs8PemObjects[0].type)
    val pkcs8FileContent = Files.readString(pkcs8File.toPath())
    print(Highlight.BLUE)
    println(pkcs8FileContent)
    print(Highlight.RESET)

    val certificates = caFile.asX509s()
    assertEquals(x509Certificate, certificates[0])

    // With password
    KaxisBcFabric.exportKeyPairToFile(aPrivate, keyEncryptedFile, pkcs8EncryptedFile, keyEncryptionAlg, "P@ssw0rd")

    // algorithm
    val keyEncryptedPemObjects = keyEncryptedFile.asPemObjects()
    assertEquals("$algorithm PRIVATE KEY", keyEncryptedPemObjects[0].type)
    val keyEncryptedFileContent = Files.readString(keyEncryptedFile.toPath())
    print(Highlight.YELLOW_BRIGHT)
    println(keyEncryptedFileContent)
    print(Highlight.RESET)

    val pkcs8EncryptedPemObjects = pkcs8EncryptedFile.asPemObjects()
    assertEquals("ENCRYPTED PRIVATE KEY", pkcs8EncryptedPemObjects[0].type)
    val pkcs8EncryptedFileContent = Files.readString(pkcs8EncryptedFile.toPath())
    print(Highlight.BLUE)
    println(pkcs8EncryptedFileContent)
    print(Highlight.RESET)
  }
}
