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

import io.kaxis.BCProvider
import io.kaxis.asAsn1s
import io.kaxis.asAsymmetricKeyParameter
import io.kaxis.asCertificate
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERBMPString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.crypto.CryptoServicesRegistrar
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder
import org.bouncycastle.operator.DefaultAlgorithmNameFinder
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder
import org.bouncycastle.pkcs.PKCSException
import org.bouncycastle.pkcs.jcajce.*
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import java.io.*
import java.math.BigInteger
import java.security.*
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.time.OffsetDateTime
import java.util.*

/**
 * Bouncycastle code generator fabric.
 * @author galudisu
 */
class KaxisBcFabric {
  companion object {
    init {
      Security.addProvider(BCProvider())
    }

    /**
     * Export X509 certificate to file.
     *
     * @param certificate [X509Certificate]
     * @param file [File]
     * @throws IOException io except.
     */
    @Throws(IOException::class)
    fun exportX509ToFileBase64Encoded(
      certificate: X509Certificate,
      file: File,
    ) {
      JcaPEMWriter(OutputStreamWriter(FileOutputStream(file))).use { certificateOut ->
        exportX509ToFileBase64Encoded(certificate, certificateOut)
      }
    }

    /**
     * Write to a string writer.
     */
    @Throws(IOException::class)
    fun exportX509ToFileBase64Encoded(
      certificate: X509Certificate,
      writer: Writer,
    ) {
      JcaPEMWriter(writer).use { certificateOut ->
        certificateOut.writeObject(certificate)
      }
    }

    /**
     * Export to file, see [exportKeyPairToFile].
     */
    @Throws(IOException::class, OperatorCreationException::class)
    fun exportKeyPairToFile(
      privateKey: PrivateKey,
      keyFile: File,
      pkcs8File: File,
      keyEncryptionAlg: ASN1ObjectIdentifier,
      passwd: String?,
    ) {
      PrintWriter(FileOutputStream(keyFile)).use { privateKeyOut ->
        PrintWriter(FileOutputStream(pkcs8File)).use { pkcs8PrivateKeyOut ->
          exportKeyPairToFile(privateKey, privateKeyOut, pkcs8PrivateKeyOut, keyEncryptionAlg, passwd)
        }
      }
    }

    /**
     * Saves the provided private key to the output file, using the requested encoding. Allows for using PKCS#8 or the legacy openssl PKCS#1 encoding.
     *
     * **WARNING**: The output stream IS NOT closed afterward. This is on purpose, so it is possible to write additional output.
     *
     * @param privateKey [PrivateKey]
     * @param keyWriter [Writer] key file
     * @param pkcs8Writer [Writer] PKCS#8 format file
     * @param keyEncryptionAlg AES-192-CBC or AES-192-ECB or DES-EDE3. Also make a ref [org.bouncycastle.openssl.bc.PEMUtilities.crypt] and [io.kaxis.extension.param.Asn1OidEnum]
     * @param passwd nullable
     * @throws IOException io except.
     * @throws OperatorCreationException operator creation exception
     */
    @Throws(IOException::class, OperatorCreationException::class)
    fun exportKeyPairToFile(
      privateKey: PrivateKey,
      keyWriter: Writer,
      pkcs8Writer: Writer,
      keyEncryptionAlg: ASN1ObjectIdentifier,
      passwd: String? = null,
    ) {
      val algorithmNameFinder = DefaultAlgorithmNameFinder()
      var encryptionAlg = "AES-256-CBC"
      if (algorithmNameFinder.hasAlgorithmName(keyEncryptionAlg)) {
        encryptionAlg = algorithmNameFinder.getAlgorithmName(keyEncryptionAlg)
        // trick
        encryptionAlg = encryptionAlg.replace("/", "-")
        if (encryptionAlg.startsWith("DESEDE-3KEY")) {
          encryptionAlg = encryptionAlg.replace("DESEDE-3KEY", "DES-EDE3")
        }
      }
      if (!encryptionAlg.startsWith("AES-") && !encryptionAlg.endsWith("-CBC") && !encryptionAlg.endsWith("RC4")) {
        throw OperatorCreationException(
          """
            |it's a pity that current version bouncy castle only compatible <AES>-<mode>-<CBC>/<PB>-<mode>-<CBC>/-<RC4>, but was $encryptionAlg
          """.trimMargin(),
        )
      }
      if (!passwd.isNullOrBlank()) {
        JcaPEMWriter(keyWriter).use { writer ->
          val pemEncryptor =
            JcePEMEncryptorBuilder(encryptionAlg).setProvider(BCProvider.PROVIDER_NAME).build(passwd.toCharArray())
          val pemGenerator = JcaMiscPEMGenerator(privateKey, pemEncryptor)
          writer.writeObject(pemGenerator)
        }
        // PKCS8
        JcaPEMWriter(pkcs8Writer).use { writer ->
          val outputEncryptor =
            JcaPKCS8EncryptedPrivateKeyInfoBuilder(privateKey).build(
              JcePKCSPBEOutputEncryptorBuilder(keyEncryptionAlg).setProvider(BCProvider.PROVIDER_NAME)
                .build(passwd.toCharArray()),
            )
          writer.writeObject(outputEncryptor)
        }
      } else {
        // warn: JCA provider is not current a ready equivalent for DomainParameters
        JcaPEMWriter(keyWriter).use { writer ->
          writer.writeObject(privateKey)
        }
        // PKCS8
        JcaPEMWriter(PrintWriter(pkcs8Writer)).use { writer ->
          writer.writeObject(JcaPKCS8Generator(privateKey, null))
        }
      }
    }

    /**
     * Export CA/Issued/Key into p12 keystore.
     *
     * @param rootCertificate [X509Certificate]
     * @param x509Certificate [X509Certificate]
     * @param privateKey [PrivateKey]
     * @param pkcs12File [File]
     * @param keyEncryptionAlg [ASN1ObjectIdentifier]
     * @param passwd nullable
     * @throws IOException io except.
     * @throws OperatorCreationException operator except.
     */
    @Throws(IOException::class, OperatorCreationException::class)
    fun exportPfxPdu(
      rootCertificate: X509Certificate,
      x509Certificate: X509Certificate,
      privateKey: PrivateKey,
      pkcs12File: File,
      keyEncryptionAlg: ASN1ObjectIdentifier,
      passwd: String? = null,
    ) {
      PrintWriter(FileOutputStream(pkcs12File)).use { writer ->
        exportPfxPdu(rootCertificate, x509Certificate, privateKey, writer, keyEncryptionAlg, passwd)
      }
    }

    /**
     * PKCS#12 keystore will store all the info(cacert/tls.crt/tls.key) within password. And the password is required.
     *
     * ```bash
     * openssl pkcs12 -info -in [filename.pfx] -nodes
     * ```
     *
     * - Extract those file:
     * ```bash
     * openssl pkcs12 -in [filename.pfx] -nocerts -nodes | openssl pkcs8 -nocrypt -out [this.key]
     * openssl pkcs12 -in [filename.pfx] -clcerts -nokeys | openssl x509 -out [tls.crt]
     * openssl pkcs12 -in [filename.pfx] -cacerts -nokeys -chain | openssl x509 -out [cacert]
     * ```
     *
     * @param rootCertificate ca
     * @param x509Certificate eeCert
     * @param privateKey private key
     * @param pkcs12Writer pkcs12 file
     * @param keyEncryptionAlg asn1Oid
     * @param passwd password for p12, or null will not write file.
     * @throws IOException io exception
     * @throws OperatorCreationException operator exp
     */
    @Throws(IOException::class, OperatorCreationException::class)
    fun exportPfxPdu(
      rootCertificate: X509Certificate,
      x509Certificate: X509Certificate,
      privateKey: PrivateKey,
      pkcs12Writer: Writer,
      keyEncryptionAlg: ASN1ObjectIdentifier,
      passwd: String? = null,
    ) {
      if (!passwd.isNullOrBlank()) {
        BufferedWriter(pkcs12Writer).use { writer ->
          val encodedPfx =
            createPfxPdu(arrayOf(x509Certificate, rootCertificate), privateKey, keyEncryptionAlg, passwd.toCharArray())
          writer.write(String(encodedPfx))
        }
      }
    }

    /**
     * Create PFX keystore.
     */
    @Throws(NoSuchAlgorithmException::class, IOException::class, OperatorCreationException::class, PKCSException::class)
    fun createPfxPdu(
      certificates: Array<X509Certificate>,
      privateKey: PrivateKey,
      keyEncryptionAlg: ASN1ObjectIdentifier,
      passwd: CharArray,
    ): ByteArray {
      require(certificates.size == 2) { "Issued X.509 and CA X.509 must be placed sequence." }

      val extUtils = JcaX509ExtensionUtils()
      val caCertBagBuilder = JcaPKCS12SafeBagBuilder(certificates[1])
      caCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, DERBMPString("CA Certificate"))
      // store the key certificate
      val eeCertBagBuilder = JcaPKCS12SafeBagBuilder(certificates[0])
      eeCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, DERBMPString("End Entity Key"))
      eeCertBagBuilder.addBagAttribute(
        PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
        extUtils.createSubjectKeyIdentifier(certificates[0].publicKey),
      )
      // store the private key
      val keyBagBuilder =
        JcaPKCS12SafeBagBuilder(
          privateKey,
          JcePKCSPBEOutputEncryptorBuilder(keyEncryptionAlg).setProvider(BCProvider.PROVIDER_NAME).build(passwd),
        )
      keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, DERBMPString("End Entity Key"))
      keyBagBuilder.addBagAttribute(
        PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
        extUtils.createSubjectKeyIdentifier(certificates[0].publicKey),
      )
      // create the actual PKCS#12 blob.
      val pfxPduBuilder = PKCS12PfxPduBuilder()
      val safeBags =
        arrayOf(
          eeCertBagBuilder.build(),
          caCertBagBuilder.build(),
        )
      pfxPduBuilder.addEncryptedData(
        JcePKCSPBEOutputEncryptorBuilder(keyEncryptionAlg).setProvider(BCProvider.PROVIDER_NAME).build(passwd),
        safeBags,
      )
      pfxPduBuilder.addData(keyBagBuilder.build())
      return pfxPduBuilder.build(JcePKCS12MacCalculatorBuilder().setProvider(BCProvider.PROVIDER_NAME), passwd).encoded
    }

    /**
     * Create the certificate time slot, if year is negative, transform to expired one.
     * @param year pre-long years
     * @return [Timeslot]
     */
    fun generateTimeSlot(year: Long): Timeslot {
      val now = OffsetDateTime.now()
      val startDate: OffsetDateTime
      val endDate: OffsetDateTime
      if (year >= 0) {
        startDate = now.minusDays(1)
        endDate = now.plusYears(year)
      } else {
        startDate = now.minusYears(-year)
        endDate = now.plusDays(1)
      }
      return Timeslot(startDate, endDate)
    }

    /**
     * Generate a CA chain.
     * @param timeslot if negative, generate an expire certificate
     * @param rootCertIssuer issuer, such as: `CN=country,L=locality,OU=organizationunit,O=organization`
     * @return [JcaKeyPair]
     */
    @Throws(
      NoSuchAlgorithmException::class,
      OperatorCreationException::class,
      IOException::class,
      CertificateException::class,
    )
    fun generateX509CaChain(
      rootKeyPair: KeyPair,
      timeslot: Timeslot,
      rootCertIssuer: X500Name,
      signatureAlgorithm: String,
    ): JcaKeyPair {
      // the first step is to create a root certificate,
      // first generate a keyPair,
      // then a random serial number,
      // then generate a certificate using the KeyPair
      val rootSerialNum = BigInteger(CryptoServicesRegistrar.getSecureRandom().nextLong().toString())

      // Issued By and Issued To same for root certificate
      val rootCertContentSigner =
        JcaContentSignerBuilder(signatureAlgorithm).setProvider(BCProvider.PROVIDER_NAME).build(rootKeyPair.private)
      val rootCertBuilder =
        JcaX509v3CertificateBuilder(
          rootCertIssuer,
          rootSerialNum,
          timeslot.startDate,
          timeslot.endDate,
          rootCertIssuer,
          rootKeyPair.public,
        )
      // Add Extensions
      // A BasicConstraint to mark root certificate as CA certificate
      val rootCertExtUtils = JcaX509ExtensionUtils()
      // some cert path analyzers will reject a v3 certificate as a CA if it doesn't have a basic constrained set.
      rootCertBuilder.addExtension(Extension.basicConstraints, true, BasicConstraints(true).encoded)
      rootCertBuilder.addExtension(
        Extension.subjectKeyIdentifier,
        false,
        rootCertExtUtils.createSubjectKeyIdentifier(rootKeyPair.public),
      )
      // Create a cert holder and export to X509Certificate
      val rootCertHolder = rootCertBuilder.build(rootCertContentSigner)
      val rootCert = JcaX509CertificateConverter().setProvider(BCProvider.PROVIDER_NAME).getCertificate(rootCertHolder)
      return JcaKeyPair(rootKeyPair, rootCert)
    }

    /**
     * Code gen.
     *
     * @param rootKeyPair [KeyPair] root
     * @param issuedCertKeyPair [KeyPair] issued
     * @param rootCert [X509Certificate] root
     * @param rootCertIssuer [X500Name] root subject
     * @param issuedCertSubject [X500Name] issued subject
     * @param timeSlot [Timeslot] expired time and create time
     * @param dnsName dns name
     * @param ipAddress ip address
     * @param signatureAlgorithm signature algorithm
     * @return [JcaKeyPair]
     * @throws OperatorCreationException operator except
     * @throws NoSuchAlgorithmException alg
     * @throws IOException io except
     * @throws CertificateException cert
     * @throws SignatureException signature
     * @throws InvalidKeyException invalid key
     * @throws NoSuchProviderException provider not found
     */
    @Throws(
      OperatorCreationException::class,
      NoSuchAlgorithmException::class,
      IOException::class,
      CertificateException::class,
      SignatureException::class,
      InvalidKeyException::class,
      NoSuchProviderException::class,
    )
    @Suppress("kotlin:S107")
    fun generateX509CertificateAndKey(
      rootKeyPair: KeyPair,
      issuedCertKeyPair: KeyPair,
      rootCert: X509Certificate,
      rootCertIssuer: X500Name,
      issuedCertSubject: X500Name,
      timeSlot: Timeslot,
      dnsName: String,
      ipAddress: String,
      signatureAlgorithm: String,
    ): JcaKeyPair {
      // Generate a new KeyPair and sign it using the Root Cert Private Key
      // by generating a CSR (Certificate Signing Request)
      val issuedCertSerialNum = BigInteger(CryptoServicesRegistrar.getSecureRandom().nextLong().toString())
      val p10Builder = JcaPKCS10CertificationRequestBuilder(issuedCertSubject, issuedCertKeyPair.public)
      val csrBuilder = JcaContentSignerBuilder(signatureAlgorithm).setProvider(BCProvider.PROVIDER_NAME)

      // Sign the new KeyPair with the root cert Private Key
      val csrContentSigner = csrBuilder.build(rootKeyPair.private)
      val csr = p10Builder.build(csrContentSigner)

      // Use the Signed KeyPair and CSR to generate an issued Certificate
      // Here serial number is randomly generated. In general, CAs use
      // a sequence to generate Serial number and avoid collisions
      val issuedCertBuilder =
        X509v3CertificateBuilder(
          rootCertIssuer,
          issuedCertSerialNum,
          timeSlot.startDate,
          timeSlot.endDate,
          csr.subject,
          csr.subjectPublicKeyInfo,
        )
      val issuedCertExtUtils = JcaX509ExtensionUtils()

      // Add Extensions
      // Use BasicConstrains to say that this Cert is not a CA
      issuedCertBuilder.addExtension(Extension.basicConstraints, true, BasicConstraints(false).encoded)

      // Add Issuer cert identifier as Extension
      issuedCertBuilder.addExtension(
        Extension.authorityKeyIdentifier,
        false,
        issuedCertExtUtils.createAuthorityKeyIdentifier(rootCert),
      )
      issuedCertBuilder.addExtension(
        Extension.subjectKeyIdentifier,
        false,
        issuedCertExtUtils.createSubjectKeyIdentifier(csr.subjectPublicKeyInfo),
      )

      // Add intended key usage extension if needed
      // **NOTE**: Only usage for digital signature since X509v3 protocol default
      issuedCertBuilder.addExtension(Extension.keyUsage, false, KeyUsage(KeyUsage.digitalSignature))

      // Add DNS name which cert is used for SSL
      issuedCertBuilder.addExtension(
        Extension.subjectAlternativeName,
        false,
        DERSequence(arrayOf(GeneralName(GeneralName.dNSName, dnsName), GeneralName(GeneralName.iPAddress, ipAddress))),
      )

      val issuedCertHolder = issuedCertBuilder.build(csrContentSigner)
      val issuedCert =
        JcaX509CertificateConverter().setProvider(BCProvider.PROVIDER_NAME).getCertificate(issuedCertHolder)

      // Verify the issued cert signature against the root (issuer) cert
      issuedCert.verify(rootCert.publicKey, BCProvider.PROVIDER_NAME)
      return JcaKeyPair(issuedCertKeyPair, issuedCert)
    }
  }

  data class Timeslot(val offsetStartDate: OffsetDateTime, val offsetEndDate: OffsetDateTime) {
    val startDate: Date
      get() = Date.from(offsetStartDate.toInstant())

    val endDate: Date
      get() = Date.from(offsetEndDate.toInstant())
  }

  data class JcaKeyPair(val keyPair: KeyPair, val x509Certificate: X509Certificate) {
    fun getAsn1X509Certificate(crypto: BcTlsCrypto): org.bouncycastle.asn1.x509.Certificate {
      return getTlsX509Certificate(crypto).asAsn1s()[0]
    }

    fun getTlsX509Certificate(crypto: BcTlsCrypto): org.bouncycastle.tls.Certificate {
      return x509Certificate.asCertificate(crypto)
    }

    val cryptoPublicAsymmetricKey: org.bouncycastle.crypto.params.AsymmetricKeyParameter
      @Throws(InvalidKeyException::class)
      get() = publicKey.asAsymmetricKeyParameter()

    val publicKey: PublicKey
      get() = keyPair.public

    val cryptoPrivateAsymmetricKey: org.bouncycastle.crypto.params.AsymmetricKeyParameter
      @Throws(InvalidKeyException::class)
      get() = privateKey.asAsymmetricKeyParameter()

    val privateKey: PrivateKey
      get() = keyPair.private
  }
}
