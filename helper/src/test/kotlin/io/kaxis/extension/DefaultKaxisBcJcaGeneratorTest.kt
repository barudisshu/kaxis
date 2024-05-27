/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.extension

import io.kaxis.*
import io.kaxis.ansi.Highlight
import io.kaxis.extension.param.AlgEnum
import io.kaxis.extension.param.AlgEnum.DSA
import io.kaxis.extension.param.AlgEnum.EC
import io.kaxis.extension.param.AlgEnum.RSA
import io.kaxis.extension.param.AlgKeySizeEnum
import io.kaxis.extension.param.AlgKeySizeEnum.*
import io.kaxis.extension.param.Asn1OidEnum
import io.kaxis.extension.param.Asn1OidEnum.*
import io.kaxis.extension.param.SigAlgEnum
import io.kaxis.extension.param.SigAlgEnum.*
import org.bouncycastle.crypto.CryptoServicesRegistrar
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.tls.Certificate
import org.bouncycastle.tls.crypto.TlsCertificate
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import org.bouncycastle.util.io.pem.PemObject
import org.junit.jupiter.api.*
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.io.TempDir
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.security.SignatureException
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

@TestMethodOrder(value = MethodOrderer.DisplayName::class)
internal class DefaultKaxisBcJcaGeneratorTest {
  @TempDir
  lateinit var tempDir: File

  companion object {
    @JvmStatic
    fun getData(): List<Arguments> {
      return listOf(
        Arguments.of(RSA, SHA_256_WITH_RSA, RSA_1024, AES_128_CBC),
        Arguments.of(RSA, SHA_1_WITH_RSA, RSA_2048, DES_EDE3_CBC),
        Arguments.of(RSA, SHA_256_WITH_RSA_AND_MGF1, RSA_1024, AES_128_CBC),
        Arguments.of(RSA, SHA_384_WITH_RSA_AND_MGF1, RSA_1024, AES_256_CBC),
        Arguments.of(RSA, SHA_512_WITH_RSA_AND_MGF1, RSA_2048, PBE_WITH_SHA_AND_128_BIT_RC4),
        Arguments.of(RSA, SHA_224_WITH_RSA_ENCRYPTION, RSA_1024, AES_192_CBC),
        Arguments.of(RSA, SHA_256_WITH_RSA_ENCRYPTION, RSA_1024, AES_128_CBC),
        Arguments.of(RSA, SHA_384_WITH_RSA_ENCRYPTION, RSA_1024, AES_256_CBC),
        Arguments.of(RSA, SHA_512_WITH_RSA_ENCRYPTION, RSA_2048, PBE_WITH_SHA_AND_128_BIT_RC4),
        Arguments.of(DSA, SHA_224_WITH_DSA, DSA_2048, AES_256_CBC),
        Arguments.of(DSA, SHA_384_WITH_DSA, DSA_1024, PBE_WITH_SHA_AND_40BIT_RC4),
        Arguments.of(DSA, SHA_512_WITH_DSA, DSA_3072, PBE_WITH_SHA_AND_3_KEY_TRIPLEDES_CBC),
        Arguments.of(EC, SHA_1_WITH_ECDSA, EC_256, PBE_WITH_SHA_AND_2_KEY_TRIPLEDES_CBC),
        Arguments.of(EC, SHA_224_WITH_ECDSA, EC_224, AES_256_CBC),
        Arguments.of(EC, SHA_384_WITH_ECDSA, EC_384, AES_256_CBC),
        Arguments.of(EC, SHA_512_WITH_ECDSA, EC_256, AES_256_CBC),
      )
    }
  }

  @ParameterizedTest(name = "0{index}: algorithm: ''{0}'', signature algorithm: ''{1}'', asn1: ''{2}''")
  @MethodSource("getData")
  @DisplayName("01 - Default.spawn")
  fun defaultSpawnTest(
    algEnum: AlgEnum,
    sigAlg: SigAlgEnum,
    keySize: AlgKeySizeEnum,
    asn1Oid: Asn1OidEnum,
  ) {
    val defaultKaxisBcJcaGenerator = DefaultKaxisBcJcaGenerator()
    val algParameter = AlgParameter(type = algEnum, algKeySize = keySize, sigAlg = sigAlg, asn1Oid = asn1Oid)

    assertEquals(asn1Oid, algParameter.asn1Oid)

    val jcaMiscPemGroove = defaultKaxisBcJcaGenerator.spawn(algParameter)
    assertNotNull(jcaMiscPemGroove)

    val rootFile = File(tempDir, algParameter.caCrtFile)
    val rootKeyFile = File(tempDir, algParameter.caKeyFile)
    val rootPkcs8File = File(tempDir, algParameter.caPkcs8File)
    val rootPkcs12File = File(tempDir, algParameter.caPkcs12File)

    jcaMiscPemGroove.exportCaToFolder(tempDir, rootFile, rootKeyFile, rootPkcs8File, rootPkcs12File, asn1Oid.asn1Oid)

    val rootPemObjects = rootFile.asPemObjects()
    assertEquals("CERTIFICATE", rootPemObjects[0].type)
    val rootFileContent = Files.readString(rootFile.toPath())
    print(Highlight.GREEN_BOLD)
    println(rootFileContent)
    print(Highlight.RESET)

    // algorithm
    val rootKeyPemObjects: List<PemObject> = rootKeyFile.asPemObjects()
    Assertions.assertEquals("${algEnum.name} PRIVATE KEY", rootKeyPemObjects[0].type)
    val rootKeyFileContent = Files.readString(rootKeyFile.toPath())
    print(Highlight.YELLOW_BRIGHT)
    println(rootKeyFileContent)
    print(Highlight.RESET)

    val rootPkcs8PemObjects: List<PemObject> = rootPkcs8File.asPemObjects()
    Assertions.assertEquals("PRIVATE KEY", rootPkcs8PemObjects[0].type)
    val rootPkcsFileContent = Files.readString(rootPkcs8File.toPath())
    print(Highlight.BLUE)
    println(rootPkcsFileContent)
    print(Highlight.RESET)

    val rootPkcs8AsymmetricKeyParameter: AsymmetricKeyParameter = rootPkcs8PemObjects[0].asAsymmetricKeyParameter()

    Assertions.assertNotNull(rootPkcs8AsymmetricKeyParameter)

    val serverFile = File(tempDir, algParameter.serverCrtFile)
    val serverKeyFile = File(tempDir, algParameter.serverKeyFile)
    val serverPkcs8File = File(tempDir, algParameter.serverPkcs8File)
    val serverPkcs12File = File(tempDir, algParameter.serverPkcs12File)

    jcaMiscPemGroove.exportServerToFolder(
      tempDir,
      serverFile,
      serverKeyFile,
      serverPkcs8File,
      serverPkcs12File,
      asn1Oid.asn1Oid,
    )

    val serverPemObjects: List<PemObject> = serverFile.asPemObjects()
    Assertions.assertEquals("CERTIFICATE", serverPemObjects[0].type)
    val serverFileContent = Files.readString(serverFile.toPath())
    print(Highlight.GREEN_BOLD)
    println(serverFileContent)
    print(Highlight.RESET)

    // algorithm
    val serverKeyEncryptedPemObjects: List<PemObject> = serverKeyFile.asPemObjects()
    Assertions.assertEquals("${algEnum.name} PRIVATE KEY", serverKeyEncryptedPemObjects[0].type)
    val serverKeyFileContent = Files.readString(serverKeyFile.toPath())
    print(Highlight.YELLOW_BRIGHT)
    println(serverKeyFileContent)
    print(Highlight.RESET)

    val serverAsymmetricKeyParameter: AsymmetricKeyParameter =
      serverKeyEncryptedPemObjects[0].asAsymmetricKeyParameter(algParameter.encryptedPass)
    Assertions.assertNotNull(serverAsymmetricKeyParameter)

    val serverPkcs8EncryptedPemObjects: List<PemObject> = serverPkcs8File.asPemObjects()
    Assertions.assertEquals("PRIVATE KEY", serverPkcs8EncryptedPemObjects[0].type)
    val serverPkcsFileContent = Files.readString(serverPkcs8File.toPath())
    print(Highlight.BLUE)
    println(serverPkcsFileContent)
    print(Highlight.RESET)

    val serverPkcs8AsymmetricKeyParameter: AsymmetricKeyParameter =
      serverPkcs8EncryptedPemObjects[0].asAsymmetricKeyParameter(algParameter.encryptedPass)

    Assertions.assertNotNull(serverPkcs8AsymmetricKeyParameter)

    val clientFile = File(tempDir, algParameter.clientCrtFile)
    val clientKeyFile = File(tempDir, algParameter.clientKeyFile)
    val clientPkcs8File = File(tempDir, algParameter.clientPkcs8File)
    val clientPkcs12File = File(tempDir, algParameter.clientPkcs12File)

    jcaMiscPemGroove.exportClientToFolder(
      tempDir,
      clientFile,
      clientKeyFile,
      clientPkcs8File,
      clientPkcs12File,
      asn1Oid.asn1Oid,
    )

    val clientPemObjects: List<PemObject> = clientFile.asPemObjects()
    Assertions.assertEquals("CERTIFICATE", clientPemObjects[0].type)
    val clientFileContent = Files.readString(clientFile.toPath())
    print(Highlight.GREEN_BOLD)
    println(clientFileContent)
    print(Highlight.RESET)

    // algorithm
    val clientKeyEncryptedPemObjects: List<PemObject> = clientKeyFile.asPemObjects()
    Assertions.assertEquals("${algEnum.name} PRIVATE KEY", clientKeyEncryptedPemObjects[0].type)
    val clientKeyFileContent = Files.readString(clientKeyFile.toPath())
    print(Highlight.YELLOW_BRIGHT)
    println(clientKeyFileContent)
    print(Highlight.RESET)

    val clientAsymmetricKeyParameter: AsymmetricKeyParameter =
      clientKeyEncryptedPemObjects[0].asAsymmetricKeyParameter(algParameter.encryptedPass)
    Assertions.assertNotNull(clientAsymmetricKeyParameter)

    val clientPkcs8EncryptedPemObjects: List<PemObject> = clientPkcs8File.asPemObjects()
    Assertions.assertEquals("PRIVATE KEY", clientPkcs8EncryptedPemObjects[0].type)
    val clientPkcsFileContent = Files.readString(clientPkcs8File.toPath())
    print(Highlight.BLUE)
    println(clientPkcsFileContent)
    print(Highlight.RESET)

    val clientPkcs8AsymmetricKeyParameter: AsymmetricKeyParameter =
      clientPkcs8EncryptedPemObjects[0].asAsymmetricKeyParameter(algParameter.encryptedPass)

    Assertions.assertNotNull(clientPkcs8AsymmetricKeyParameter)

    val bcTlsCrypto = BcTlsCrypto(CryptoServicesRegistrar.getSecureRandom())
    val caCertificate: Certificate = jcaMiscPemGroove.caGroove.getTlsX509Certificate(bcTlsCrypto)
    val serverCertificate: Certificate =
      jcaMiscPemGroove.serverGroove.getTlsX509Certificate(bcTlsCrypto)
    val clientCertificate: Certificate =
      jcaMiscPemGroove.clientGroove.getTlsX509Certificate(bcTlsCrypto)

    assertTrue(verifyExchangeCertificate(caCertificate, caCertificate))
    Assertions.assertDoesNotThrow {
      verifyCertificateChain(
        Certificate(
          arrayOf<TlsCertificate>(
            serverCertificate.getCertificateAt(0),
            caCertificate.getCertificateAt(0),
          ),
        ),
      )
    }

    // wrap entry order
    Assertions.assertThrows(
      SignatureException::class.java,
    ) {
      verifyCertificateChain(
        Certificate(
          arrayOf<TlsCertificate>(
            caCertificate.getCertificateAt(0),
            serverCertificate.getCertificateAt(0),
          ),
        ),
      )
    }

    Assertions.assertDoesNotThrow {
      verifyIssuedExpired(
        caCertificate,
      )
    }
    Assertions.assertDoesNotThrow {
      verifyIssuedExpired(
        serverCertificate,
      )
    }
    Assertions.assertDoesNotThrow {
      verifyIssuedExpired(
        clientCertificate,
      )
    }
    assertTrue(verifyIssuedCertAssignFrom(serverCertificate, caCertificate))
    assertTrue(verifyIssuedCertAssignFrom(clientCertificate, caCertificate))
  }

  @ParameterizedTest(name = "0{index}: algorithm: ''{0}'', signature algorithm: ''{1}'', asn1: ''{2}''")
  @MethodSource("getData")
  @DisplayName("02 - Custom.spawn")
  fun customSpawnTest(
    algEnum: AlgEnum,
    sigAlg: SigAlgEnum,
    keySize: AlgKeySizeEnum,
    asn1Oid: Asn1OidEnum,
  ) {
    val crypto = BcTlsCrypto(CryptoServicesRegistrar.getSecureRandom())
    val defaultKaxisBcJcaGenerator = DefaultKaxisBcJcaGenerator()
    val jcaMiscPemGroove =
      defaultKaxisBcJcaGenerator.spawn(
        AlgParameter(
          type = algEnum,
          algKeySize = keySize,
          sigAlg = sigAlg,
          asn1Oid = asn1Oid,
        ),
      )
    assertNotNull(jcaMiscPemGroove)
    assertNotNull(jcaMiscPemGroove.id)

    val rootFile = File(tempDir, "root.crt")
    val rootKeyFile = File(tempDir, "rootEncrypted.key")
    val rootPkcs8File = File(tempDir, "rootPkcs8Encrypted.key")
    val rootPkcs12File = File(tempDir, "root.p12")

    assertThrows<IOException> {
      jcaMiscPemGroove.exportCaToFolder(rootFile, rootFile, rootKeyFile, rootPkcs8File, rootPkcs12File, asn1Oid.asn1Oid)
    }

    jcaMiscPemGroove.exportCaToFolder(tempDir, rootFile, rootKeyFile, rootPkcs8File, rootPkcs12File, asn1Oid.asn1Oid)
    val rootPemObjects = rootFile.asPemObjects()
    assertEquals("CERTIFICATE", rootPemObjects[0].type)
    assertEquals(jcaMiscPemGroove.caGroove.x509Certificate, rootFile.asX509s()[0])
    assertNotNull(jcaMiscPemGroove.caGroove.cryptoPublicAsymmetricKey)
    assertNotNull(jcaMiscPemGroove.caGroove.cryptoPrivateAsymmetricKey)
    assertNotNull(jcaMiscPemGroove.caGroove.getTlsX509Certificate(crypto))
    assertNotNull(jcaMiscPemGroove.caGroove.getAsn1X509Certificate(crypto))
    val rootFileContent = Files.readString(rootFile.toPath())
    print(Highlight.GREEN_BOLD)
    println(rootFileContent)
    print(Highlight.RESET)

    // algorithm
    val rootKeyPemObjects = rootKeyFile.asPemObjects()
    assertEquals("${algEnum.name} PRIVATE KEY", rootKeyPemObjects[0].type)
    val rootKeyFileContent = Files.readString(rootKeyFile.toPath())
    print(Highlight.YELLOW_BRIGHT)
    println(rootKeyFileContent)
    print(Highlight.RESET)

    val rootPkcs8PemObjects = rootPkcs8File.asPemObjects()
    Assertions.assertEquals("PRIVATE KEY", rootPkcs8PemObjects[0].type)
    val rootPkcsFileContent = Files.readString(rootPkcs8File.toPath())
    print(Highlight.BLUE)
    println(rootPkcsFileContent)
    print(Highlight.RESET)

    val rootPkcs8AsymmetricKeyParameter = rootPkcs8PemObjects[0].asAsymmetricKeyParameter()
    assertNotNull(rootPkcs8AsymmetricKeyParameter)

    val serverFile = File(tempDir, "server.crt")
    val serverKeyFile = File(tempDir, "serverEncrypted.key")
    val serverPkcs8File = File(tempDir, "serverPkcs8Encrypted.key")
    val serverPkcs12File = File(tempDir, "server.p12")

    jcaMiscPemGroove.exportServerToFolder(
      tempDir,
      serverFile,
      serverKeyFile,
      serverPkcs8File,
      serverPkcs12File,
      asn1Oid.asn1Oid,
      "P@ssw0rd",
      "server",
    )

    val serverPemObjects = serverFile.asPemObjects()
    assertEquals("CERTIFICATE", serverPemObjects[0].type)
    assertEquals(jcaMiscPemGroove.serverGroove.x509Certificate, serverFile.asX509s()[0])
    assertNotNull(jcaMiscPemGroove.serverGroove.cryptoPublicAsymmetricKey)
    assertNotNull(jcaMiscPemGroove.serverGroove.cryptoPrivateAsymmetricKey)
    assertNotNull(jcaMiscPemGroove.serverGroove.getTlsX509Certificate(crypto))
    assertNotNull(jcaMiscPemGroove.serverGroove.getAsn1X509Certificate(crypto))
    val serverFileContent = Files.readString(serverFile.toPath())
    print(Highlight.GREEN_BOLD)
    println(serverFileContent)
    print(Highlight.RESET)

    // algorithm
    val serverKeyEncryptedPemObjects = serverKeyFile.asPemObjects()
    Assertions.assertEquals("${algEnum.name} PRIVATE KEY", serverKeyEncryptedPemObjects[0].type)
    val serverKeyFileContent = Files.readString(serverKeyFile.toPath())
    print(Highlight.YELLOW_BRIGHT)
    println(serverKeyFileContent)
    print(Highlight.RESET)

    val serverAsymmetricKeyParameter = serverKeyEncryptedPemObjects[0].asAsymmetricKeyParameter("P@ssw0rd")
    Assertions.assertNotNull(serverAsymmetricKeyParameter)

    val serverPkcs8EncryptedPemObjects = serverPkcs8File.asPemObjects()
    Assertions.assertEquals("ENCRYPTED PRIVATE KEY", serverPkcs8EncryptedPemObjects[0].type)
    val serverPkcsFileContent = Files.readString(serverPkcs8File.toPath())
    print(Highlight.BLUE)
    println(serverPkcsFileContent)
    print(Highlight.RESET)

    val serverPkcs8AsymmetricKeyParameter: AsymmetricKeyParameter =
      serverPkcs8EncryptedPemObjects[0].asAsymmetricKeyParameter("P@ssw0rd")

    Assertions.assertNotNull(serverPkcs8AsymmetricKeyParameter)

    val clientFile = File(tempDir, "client.crt")
    val clientKeyFile = File(tempDir, "clientEncrypted.key")
    val clientPkcs8File = File(tempDir, "clientPkcs8Encrypted.key")
    val clientPkcs12File = File(tempDir, "client.p12")

    jcaMiscPemGroove.exportClientToFolder(
      tempDir,
      clientFile,
      clientKeyFile,
      clientPkcs8File,
      clientPkcs12File,
      asn1Oid.asn1Oid,
      "ChangeMe1",
      "client",
    )

    val clientPemObjects = clientFile.asPemObjects()
    assertEquals("CERTIFICATE", clientPemObjects[0].type)
    assertEquals(jcaMiscPemGroove.clientGroove.x509Certificate, clientFile.asX509s()[0])
    assertNotNull(jcaMiscPemGroove.clientGroove.cryptoPublicAsymmetricKey)
    assertNotNull(jcaMiscPemGroove.clientGroove.cryptoPrivateAsymmetricKey)
    assertNotNull(jcaMiscPemGroove.clientGroove.getTlsX509Certificate(crypto))
    assertNotNull(jcaMiscPemGroove.clientGroove.getAsn1X509Certificate(crypto))
    val clientFileContent = Files.readString(clientFile.toPath())
    print(Highlight.GREEN_BOLD)
    println(clientFileContent)
    print(Highlight.RESET)

    // algorithm
    val clientKeyEncryptedPemObjects = clientKeyFile.asPemObjects()
    Assertions.assertEquals("${algEnum.name} PRIVATE KEY", clientKeyEncryptedPemObjects[0].type)
    val clientKeyFileContent = Files.readString(clientKeyFile.toPath())
    print(Highlight.YELLOW_BRIGHT)
    println(clientKeyFileContent)
    print(Highlight.RESET)

    val clientAsymmetricKeyParameter = clientKeyEncryptedPemObjects[0].asAsymmetricKeyParameter("ChangeMe1")
    Assertions.assertNotNull(clientAsymmetricKeyParameter)

    val clientPkcs8EncryptedPemObjects = clientPkcs8File.asPemObjects()
    Assertions.assertEquals("ENCRYPTED PRIVATE KEY", clientPkcs8EncryptedPemObjects[0].type)
    val clientPkcsFileContent = Files.readString(clientPkcs8File.toPath())
    print(Highlight.BLUE)
    println(clientPkcsFileContent)
    print(Highlight.RESET)

    val clientPkcs8AsymmetricKeyParameter: AsymmetricKeyParameter =
      clientPkcs8EncryptedPemObjects[0].asAsymmetricKeyParameter("ChangeMe1")

    Assertions.assertNotNull(clientPkcs8AsymmetricKeyParameter)
  }

  @ParameterizedTest(
    name = "0{index}: algorithm: ''{0}'', signature algorithm: ''{1}'', asn1: ''{2}''",
  )
  @MethodSource("getData")
  @DisplayName("03 - Writer.spawn")
  fun writerSpawnTest(
    algEnum: AlgEnum,
    sigAlg: SigAlgEnum,
    keySize: AlgKeySizeEnum,
    asn1Oid: Asn1OidEnum,
  ) {
    val defaultKaxisBcJcaGenerator = DefaultKaxisBcJcaGenerator()
    val algParameter = AlgParameter(type = algEnum, algKeySize = keySize, sigAlg = sigAlg, asn1Oid = asn1Oid)
    assertEquals(asn1Oid, algParameter.asn1Oid)

    val jcaMiscPemGroove = defaultKaxisBcJcaGenerator.spawn(algParameter)
    assertNotNull(jcaMiscPemGroove)

    val caArray = jcaMiscPemGroove.exportCaToString(asn1Oid.asn1Oid, "P@ssw0rd", "ChangeMe1")
    val serverArray = jcaMiscPemGroove.exportServerToString(asn1Oid.asn1Oid, "P@ssw0rd", "ChangeMe1")
    val clientArray = jcaMiscPemGroove.exportClientToString(asn1Oid.asn1Oid, "P@ssw0rd", "ChangeMe1")

    assertEquals(4, caArray.size)
    assertEquals(4, serverArray.size)
    assertEquals(4, clientArray.size)
  }
}
