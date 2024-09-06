/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis

import io.kaxis.wrapper.*
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers
import org.bouncycastle.asn1.eac.EACObjectIdentifiers
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.DSAParameter
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.cert.CertIOException
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.crypto.params.*
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil
import org.bouncycastle.openssl.PEMException
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.pkcs.PKCSException
import org.bouncycastle.tls.*
import org.bouncycastle.tls.Certificate
import org.bouncycastle.tls.crypto.TlsCertificate
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCertificate
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import org.bouncycastle.util.BigIntegers
import org.bouncycastle.util.encoders.Hex
import org.bouncycastle.util.io.pem.PemHeader
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemReader
import java.io.*
import java.security.*
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.security.interfaces.*
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec
import java.util.*

// ///////////////////////////////////////////////////////////////////////////

const val X509_ALGORITHM = "X.509"
const val CERTIFICATE_PEM_TYPE = "CERTIFICATE"

const val RSA = "RSA"
const val DSA = "DSA"
const val ECDSA = "EC"

typealias BCProvider = org.bouncycastle.jce.provider.BouncyCastleProvider

val ProviderNo = Security.addProvider(BCProvider()) // <1> Always setup security provider.

val key_factories = mutableMapOf<String, KeyFactory?>()
val cert_sig_alg_oids =
  Hashtable<String, SignatureAndHashAlgorithm>().apply h@{
    addCertSigAlgOid(
      this@h,
      NISTObjectIdentifiers.dsa_with_sha224,
      HashAlgorithm.sha224,
      SignatureAlgorithm.dsa,
    )
    addCertSigAlgOid(
      this@h,
      NISTObjectIdentifiers.dsa_with_sha256,
      HashAlgorithm.sha256,
      SignatureAlgorithm.dsa,
    )
    addCertSigAlgOid(
      this@h,
      NISTObjectIdentifiers.dsa_with_sha384,
      HashAlgorithm.sha384,
      SignatureAlgorithm.dsa,
    )
    addCertSigAlgOid(
      this@h,
      NISTObjectIdentifiers.dsa_with_sha512,
      HashAlgorithm.sha512,
      SignatureAlgorithm.dsa,
    )

    addCertSigAlgOid(
      this@h,
      OIWObjectIdentifiers.dsaWithSHA1,
      HashAlgorithm.sha1,
      SignatureAlgorithm.dsa,
    )
    addCertSigAlgOid(
      this@h,
      OIWObjectIdentifiers.sha1WithRSA,
      HashAlgorithm.sha1,
      SignatureAlgorithm.rsa,
    )

    addCertSigAlgOid(
      this@h,
      PKCSObjectIdentifiers.sha1WithRSAEncryption,
      HashAlgorithm.sha1,
      SignatureAlgorithm.rsa,
    )
    addCertSigAlgOid(
      this@h,
      PKCSObjectIdentifiers.sha224WithRSAEncryption,
      HashAlgorithm.sha224,
      SignatureAlgorithm.rsa,
    )
    addCertSigAlgOid(
      this@h,
      PKCSObjectIdentifiers.sha256WithRSAEncryption,
      HashAlgorithm.sha256,
      SignatureAlgorithm.rsa,
    )
    addCertSigAlgOid(
      this@h,
      PKCSObjectIdentifiers.sha384WithRSAEncryption,
      HashAlgorithm.sha384,
      SignatureAlgorithm.rsa,
    )
    addCertSigAlgOid(
      this@h,
      PKCSObjectIdentifiers.sha512WithRSAEncryption,
      HashAlgorithm.sha512,
      SignatureAlgorithm.rsa,
    )

    addCertSigAlgOid(
      this@h,
      X9ObjectIdentifiers.ecdsa_with_SHA1,
      HashAlgorithm.sha1,
      SignatureAlgorithm.ecdsa,
    )
    addCertSigAlgOid(
      this@h,
      X9ObjectIdentifiers.ecdsa_with_SHA224,
      HashAlgorithm.sha224,
      SignatureAlgorithm.ecdsa,
    )
    addCertSigAlgOid(
      this@h,
      X9ObjectIdentifiers.ecdsa_with_SHA256,
      HashAlgorithm.sha256,
      SignatureAlgorithm.ecdsa,
    )
    addCertSigAlgOid(
      this@h,
      X9ObjectIdentifiers.ecdsa_with_SHA384,
      HashAlgorithm.sha384,
      SignatureAlgorithm.ecdsa,
    )
    addCertSigAlgOid(
      this@h,
      X9ObjectIdentifiers.ecdsa_with_SHA512,
      HashAlgorithm.sha512,
      SignatureAlgorithm.ecdsa,
    )
    addCertSigAlgOid(
      this@h,
      X9ObjectIdentifiers.id_dsa_with_sha1,
      HashAlgorithm.sha1,
      SignatureAlgorithm.dsa,
    )

    addCertSigAlgOid(
      this@h,
      EACObjectIdentifiers.id_TA_ECDSA_SHA_1,
      HashAlgorithm.sha1,
      SignatureAlgorithm.ecdsa,
    )
    addCertSigAlgOid(
      this@h,
      EACObjectIdentifiers.id_TA_ECDSA_SHA_224,
      HashAlgorithm.sha224,
      SignatureAlgorithm.ecdsa,
    )
    addCertSigAlgOid(
      this@h,
      EACObjectIdentifiers.id_TA_ECDSA_SHA_256,
      HashAlgorithm.sha256,
      SignatureAlgorithm.ecdsa,
    )
    addCertSigAlgOid(
      this@h,
      EACObjectIdentifiers.id_TA_ECDSA_SHA_384,
      HashAlgorithm.sha384,
      SignatureAlgorithm.ecdsa,
    )
    addCertSigAlgOid(
      this@h,
      EACObjectIdentifiers.id_TA_ECDSA_SHA_512,
      HashAlgorithm.sha512,
      SignatureAlgorithm.ecdsa,
    )
    addCertSigAlgOid(
      this@h,
      EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_1,
      HashAlgorithm.sha1,
      SignatureAlgorithm.rsa,
    )
    addCertSigAlgOid(
      this@h,
      EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_256,
      HashAlgorithm.sha256,
      SignatureAlgorithm.rsa,
    )

    addCertSigAlgOid(
      this@h,
      BSIObjectIdentifiers.ecdsa_plain_SHA1,
      HashAlgorithm.sha1,
      SignatureAlgorithm.ecdsa,
    )
    addCertSigAlgOid(
      this@h,
      BSIObjectIdentifiers.ecdsa_plain_SHA224,
      HashAlgorithm.sha224,
      SignatureAlgorithm.ecdsa,
    )
    addCertSigAlgOid(
      this@h,
      BSIObjectIdentifiers.ecdsa_plain_SHA256,
      HashAlgorithm.sha256,
      SignatureAlgorithm.ecdsa,
    )
    addCertSigAlgOid(
      this@h,
      BSIObjectIdentifiers.ecdsa_plain_SHA384,
      HashAlgorithm.sha384,
      SignatureAlgorithm.ecdsa,
    )
    addCertSigAlgOid(
      this@h,
      BSIObjectIdentifiers.ecdsa_plain_SHA512,
      HashAlgorithm.sha512,
      SignatureAlgorithm.ecdsa,
    )

    addCertSigAlgOid(this@h, EdECObjectIdentifiers.id_Ed25519, SignatureAndHashAlgorithm.ed25519)
    addCertSigAlgOid(this@h, EdECObjectIdentifiers.id_Ed448, SignatureAndHashAlgorithm.ed448)

    addCertSigAlgOid(
      this@h,
      RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256,
      SignatureAndHashAlgorithm.gostr34102012_256,
    )
    addCertSigAlgOid(
      this@h,
      RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512,
      SignatureAndHashAlgorithm.gostr34102012_512,
    )
  }

/**
 * Only support symmetric cryptography, or else throw exception.
 */
@Throws(NoSuchAlgorithmException::class)
fun getKeyFactory(algorithm: String): KeyFactory {
  synchronized(key_factories) {
    val kf = key_factories[algorithm]
    return if (kf != null) {
      kf
    } else {
      val fb = KeyFactory.getInstance(algorithm, BCProvider.PROVIDER_NAME)
      key_factories[algorithm] = fb
      fb
    }
  }
}

@Suppress("UNCHECKED_CAST")
inline fun <reified T : Any> List<*>.checkItemsAre() =
  if (this.all { it is T }) {
    this as List<T>
  } else {
    null
  }

fun <T> List<T>.asCertificate(crypto: BcTlsCrypto): Certificate {
  val pemObjects = checkItemsAre<PemObject>()
  if (pemObjects != null) {
    val tlsCertificates = arrayListOf<TlsCertificate>()
    pemObjects.forEach { pemObject ->
      if (pemObject.type.endsWith(CERTIFICATE_PEM_TYPE)) {
        val certificate = crypto.createCertificate(pemObject.content)
        tlsCertificates.add(certificate)
      }
    }
    return Certificate(tlsCertificates.toTypedArray())
  }

  val x509Certificates = checkItemsAre<X509Certificate>()
  if (x509Certificates != null) {
    return Certificate(x509Certificates.map { BcTlsCertificate(crypto, it.encoded) }.toTypedArray())
  }
  throw PEMException("List object of PEM type doesn't match.")
}

fun X509Certificate.asCertificate(crypto: BcTlsCrypto): Certificate {
  return Certificate(arrayOf(BcTlsCertificate(crypto, this.encoded)))
}

/**
 * Read file to TLS [Certificate].
 * @param crypto crypto secure
 * @return [Certificate]
 * @throws IOException io excpet.
 */
fun File.asCertificate(crypto: BcTlsCrypto): Certificate {
  val pemObjects = asPemObjects()
  return pemObjects.asCertificate(crypto)
}

@Throws(CertificateException::class, IOException::class)
fun File.asX509s(): List<X509Certificate> {
  val x509Certificates = arrayListOf<X509Certificate>()
  FileReader(this).use { file ->
    x509Certificates.addAll(file.asX509s())
  }
  return x509Certificates
}

@Throws(CertificateException::class, IOException::class)
fun Reader.asX509s(): List<X509Certificate> {
  val x509Certificates = arrayListOf<X509Certificate>()
  PemReader(this).use { pemReader ->
    var hasNext = true
    while (hasNext) {
      val pemObject = pemReader.readPemObject()
      if (pemObject != null) {
        x509Certificates.add(pemObject.asX509())
      } else {
        hasNext = false
      }
    }
  }
  return x509Certificates
}

@Throws(IOException::class)
fun String.asCertificate(crypto: BcTlsCrypto): Certificate {
  val pemObjects = asPemObjects()
  return pemObjects.asCertificate(crypto)
}

fun File.asPemObjects(): List<PemObject> {
  return InputStreamReader(FileInputStream(this)).use { it.asPemObjects() }
}

fun Reader.asPemObjects(): List<PemObject> {
  val pemObjects = arrayListOf<PemObject>()
  PemReader(this).use { pemReader ->
    var hasNext = true
    while (hasNext) {
      val pemObject = pemReader.readPemObject()
      if (pemObject != null) {
        pemObjects.add(pemObject)
      } else {
        hasNext = false
      }
    }
  }
  return pemObjects
}

fun String.asPemObjects(): List<PemObject> {
  return StringReader(this).asPemObjects()
}

@Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
fun SubjectPublicKeyInfo.asPublicKey(): PublicKey {
  val keySpec = X509EncodedKeySpec(this.encoded)
  val algorithm =
    when (val alg = this.algorithm.algorithm) {
      PKCSObjectIdentifiers.rsaEncryption -> RSA
      X9ObjectIdentifiers.id_dsa -> DSA
      X9ObjectIdentifiers.id_ecPublicKey -> ECDSA
      else -> throw InvalidKeySpecException("unsupported key algorithm: $alg")
    }
  val kf = getKeyFactory(algorithm)
  synchronized(key_factories) {
    return kf.generatePublic(keySpec)
  }
}

@Throws(
  CertificateException::class,
  IOException::class,
  InvalidKeySpecException::class,
  OperatorCreationException::class,
  PKCSException::class,
)
fun Reader.asAsymmetricKeyParameter(keyPass: String? = null): AsymmetricKeyParameter {
  PemReader(this).use { pemReader ->
    val pemObject = pemReader.readPemObject()
    return pemObject.asAsymmetricKeyParameter(keyPass)
  }
}

@Throws(
  CertificateException::class,
  IOException::class,
  InvalidKeySpecException::class,
  OperatorCreationException::class,
  PKCSException::class,
)
fun File.asAsymmetricKeyParameter(keyPass: String? = null): AsymmetricKeyParameter {
  return FileReader(this).asAsymmetricKeyParameter(keyPass)
}

@Throws(
  CertificateException::class,
  IOException::class,
  InvalidKeySpecException::class,
  OperatorCreationException::class,
  PKCSException::class,
)
fun String.asAsymmetricKeyParameter(keyPass: String? = null): AsymmetricKeyParameter {
  return StringReader(this).asAsymmetricKeyParameter(keyPass)
}

@Throws(InvalidKeySpecException::class)
fun PublicKey.asAsymmetricKeyParameter(): AsymmetricKeyParameter {
  return when (this) {
    is RSAPublicKey -> RSAKeyParameters(false, this.modulus, this.publicExponent)
    is DSAPublicKey -> DSAUtil.generatePublicKeyParameter(this)
    is ECPublicKey -> ECUtil.generatePublicKeyParameter(this)
    else -> throw InvalidKeySpecException("Unknown key ${this.javaClass.name}")
  }
}

fun Certificate.asAsn1s(): List<org.bouncycastle.asn1.x509.Certificate> {
  return this.certificateList.map { org.bouncycastle.asn1.x509.Certificate.getInstance(it.encoded) }
}

fun Certificate.asX509s(): List<X509Certificate> {
  val converter = JcaX509CertificateConverter().setProvider(BCProvider.PROVIDER_NAME)
  return this.asAsn1s().map { X509CertificateHolder(it) }.map { converter.getCertificate(it) }
}

@Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
fun org.bouncycastle.asn1.x509.Certificate.asPublicKey(): PublicKey {
  return this.subjectPublicKeyInfo.asPublicKey()
}

/**
 * Check whether trust CA or issue certificate.
 */
fun X509Certificate.isCa(): Boolean {
  return if (this.basicConstraints != -1) {
    true
  } else if (this.keyUsage != null) {
    this.keyUsage[5]
  } else {
    false
  }
}

@Throws(CertificateException::class)
fun PemObject.asX509(): X509Certificate {
  when (this.type) {
    "CERTIFICATE" -> {
      val converter = JcaX509CertificateConverter().setProvider(BCProvider.PROVIDER_NAME)
      val x509CertificateHolder = X509CertificateHolder(this.content)
      return converter.getCertificate(x509CertificateHolder)
    }

    else -> throw CertificateException("invalid certificate")
  }
}

/**
 * Read PEM format file into PEM object, and extra it's asymmetric key parameter.
 */
@Suppress("kotlin:S3776")
@Throws(
  PKCSException::class,
  PEMException::class,
  InvalidKeySpecException::class,
  IOException::class,
  OperatorCreationException::class,
  CertificateException::class,
)
fun PemObject.asAsymmetricKeyParameter(pass: String? = null): AsymmetricKeyParameter {
  return when (this.type) {
    "RSA PRIVATE KEY" -> readRsaAsymmetricKeyParameter(pass)
    "EC PRIVATE KEY" -> readEcAsymmetricKeyParameter(pass)
    "DSA PRIVATE KEY" -> readDsaAsymmetricKeyParameter(pass)
    "DSA PARAMETERS" -> readDsaPrivateKeyParameters()
    "EC PARAMETERS" -> readEcPrivateKeyParameters()
    "PRIVATE KEY" -> PrivateKeyFactory.createKey(this.content)
    "ENCRYPTED PRIVATE KEY" -> readPkcs8EncryptedAsymmetricKeyParameter(pass)
    CERTIFICATE_PEM_TYPE -> this.asPublicKey().asAsymmetricKeyParameter()

    else -> throw InvalidKeySpecException("Unknown key type ${this.type}")
  }
}

@Throws(InvalidKeySpecException::class)
private fun extractHeaderInfos(pemObject: PemObject): Pair<Boolean, String?> {
  var headerInfo = Pair<Boolean, String?>(false, null)
  for (header in pemObject.headers) {
    when (header) {
      is PemHeader -> {
        if (header.name == "Proc-Type" && header.value == "4,ENCRYPTED") {
          headerInfo = headerInfo.copy(first = true)
        } else if (header.name == "DEK-Info") {
          headerInfo = headerInfo.copy(second = header.value)
        }
      }

      else -> throw InvalidKeySpecException("unknown PemObject Header type $header")
    }
  }
  return headerInfo
}

/** Decrypted RSA/DSA/ECDSA content with pass. */
@Throws(PEMException::class)
private fun readEncryptedDerContent(
  dekInfo: String,
  encryptContent: ByteArray,
  pass: String,
): ByteArray {
  val tknz = StringTokenizer(dekInfo, ",")
  val dekAlgName = tknz.nextToken()
  val iv = Hex.decode(tknz.nextToken())
  val provider = BcPEMDecryptorProvider(pass.toCharArray())
  val keyDecryptor = provider[dekAlgName]
  return keyDecryptor.decrypt(encryptContent, iv)
}

@Throws(IOException::class, InvalidKeySpecException::class)
private fun PemObject.readEcAsymmetricKeyParameter(pass: String? = null): AsymmetricKeyParameter {
  if (!pass.isNullOrBlank()) {
    val (isEncrypted, dekInfo) = extractHeaderInfos(this)
    if (isEncrypted) {
      if (dekInfo != null) {
        val encoding = readEncryptedDerContent(dekInfo, this.content, pass)
        return readEcPemObjectCoPasswdToAsymmetricKeyParameter(encoding)
      } else {
        throw PEMException("malformed sequence in EC private key")
      }
    } else {
      return readEcPemObjectCoPasswdToAsymmetricKeyParameter(this.content)
    }
  } else {
    return readEcPemObjectCoPasswdToAsymmetricKeyParameter(this.content)
  }
}

@Throws(IOException::class)
private fun readRsaPemObjectCoPasswdToAsymmetricKeyParameter(encoding: ByteArray): AsymmetricKeyParameter {
  val keyStruct = org.bouncycastle.asn1.pkcs.RSAPrivateKey.getInstance(encoding)
  val pubSpec = org.bouncycastle.asn1.pkcs.RSAPublicKey(keyStruct.modulus, keyStruct.publicExponent)
  val algId = AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE)
  val keyPair = PEMKeyPair(SubjectPublicKeyInfo(algId, pubSpec), PrivateKeyInfo(algId, keyStruct))
  return PrivateKeyFactory.createKey(keyPair.privateKeyInfo)
}

@Throws(IOException::class)
private fun readEcPemObjectCoPasswdToAsymmetricKeyParameter(encoding: ByteArray): AsymmetricKeyParameter {
  val seq = ASN1Sequence.getInstance(encoding)
  val ecPrivateKey = org.bouncycastle.asn1.sec.ECPrivateKey.getInstance(seq)
  val algId = AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, ecPrivateKey.parametersObject)
  val privInfo = PrivateKeyInfo(algId, ecPrivateKey)
  return PrivateKeyFactory.createKey(privInfo)
}

@Throws(IOException::class)
private fun readDsaPemObjectCoPasswdToAsymmetricKeyParameter(encoding: ByteArray): AsymmetricKeyParameter {
  val seq = ASN1Sequence.getInstance(encoding)
  if (seq.size() != 6) {
    throw PEMException("malformed sequence in DSA private key")
  }
  val p = ASN1Integer.getInstance(seq.getObjectAt(1))
  val q = ASN1Integer.getInstance(seq.getObjectAt(2))
  val g = ASN1Integer.getInstance(seq.getObjectAt(3))
  val y = ASN1Integer.getInstance(seq.getObjectAt(4))
  val x = ASN1Integer.getInstance(seq.getObjectAt(5))
  val keyPair =
    PEMKeyPair(
      SubjectPublicKeyInfo(AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, DSAParameter(p.value, q.value, g.value)), y),
      PrivateKeyInfo(
        AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, DSAParameter(p.value, q.value, g.value)),
        x,
      ),
    )
  return PrivateKeyFactory.createKey(keyPair.privateKeyInfo)
}

@Throws(IOException::class, InvalidKeySpecException::class)
private fun PemObject.readDsaAsymmetricKeyParameter(pass: String? = null): AsymmetricKeyParameter {
  if (!pass.isNullOrBlank()) {
    val (isEncrypted, dekInfo) = extractHeaderInfos(this)
    if (isEncrypted) {
      if (dekInfo != null) {
        val encoding = readEncryptedDerContent(dekInfo, this.content, pass)
        return readDsaPemObjectCoPasswdToAsymmetricKeyParameter(encoding)
      } else {
        throw PEMException("malformed sequence in DSA private key")
      }
    } else {
      return readDsaPemObjectCoPasswdToAsymmetricKeyParameter(this.content)
    }
  } else {
    return readDsaPemObjectCoPasswdToAsymmetricKeyParameter(this.content)
  }
}

@Throws(IOException::class)
private fun PemObject.readDsaPrivateKeyParameters(): AsymmetricKeyParameter {
  val pKey = DSAParameter.getInstance(this.content)
  val dsaParams = DSAParameters(pKey.p, pKey.g, pKey.q)
  return DSAPrivateKeyParameters(pKey.g, dsaParams)
}

/**
 * EC Curve Params.
 */
@Throws(IOException::class)
private fun PemObject.readEcPrivateKeyParameters(): AsymmetricKeyParameter {
  val asn1Primitive = ASN1Primitive.fromByteArray(this.content)
  val x9EcParameters = ECNamedCurveTable.getByOID(ASN1ObjectIdentifier.getInstance(asn1Primitive))
  // get named
  val ecName = ECNamedCurveTable.getName(ASN1ObjectIdentifier.getInstance(asn1Primitive))
  val secureRandom = SecureRandom(x9EcParameters.seed)
  var ecDomainParameters = ECDomainParameters(x9EcParameters)
  if (ecName != null) {
    ecDomainParameters = ECNamedDomainParameters(ASN1ObjectIdentifier.getInstance(asn1Primitive), x9EcParameters)
  }
  return ECPrivateKeyParameters(BigIntegers.createRandomBigInteger(16, secureRandom), ecDomainParameters)
}

private fun PemObject.readPkcs8EncryptedAsymmetricKeyParameter(pass: String? = null): AsymmetricKeyParameter {
  if (pass != null) {
    val pInfo =
      org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo(
        org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo.getInstance(this.content),
      )
    val decryptContent =
      pInfo.decryptPrivateKeyInfo(
        org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider(BCProvider.PROVIDER_NAME)
          .build(pass.toCharArray()),
      )
    return PrivateKeyFactory.createKey(decryptContent)
  } else {
    throw PKCSException("Unable to parse pkcs8 encrypted private key, because password is NULL")
  }
}

/**
 * Read rsa encrypted content.
 */
@Throws(IOException::class, PEMException::class)
private fun PemObject.readRsaAsymmetricKeyParameter(pass: String? = null): AsymmetricKeyParameter {
  if (!pass.isNullOrBlank()) {
    val (isEncrypted, dekInfo) = extractHeaderInfos(this)
    if (isEncrypted) {
      if (dekInfo != null) {
        val encoding = readEncryptedDerContent(dekInfo, this.content, pass)
        return readRsaPemObjectCoPasswdToAsymmetricKeyParameter(encoding)
      } else {
        throw PEMException("malformed sequence in RSA private key")
      }
    } else {
      return readRsaPemObjectCoPasswdToAsymmetricKeyParameter(this.content)
    }
  } else {
    val rsa = org.bouncycastle.asn1.pkcs.RSAPrivateKey.getInstance(this.content)
    return RSAPrivateCrtKeyParameters(
      rsa.modulus,
      rsa.publicExponent,
      rsa.privateExponent,
      rsa.prime1,
      rsa.prime2,
      rsa.exponent1,
      rsa.exponent2,
      rsa.coefficient,
    )
  }
}

/**
 * convert to a public key from asymmetricKeyParameter
 */
fun AsymmetricKeyParameter.asPublicKey(): PublicKey {
  return if (this.isPrivate) {
    throw InvalidKeySpecException("AsymmetricKeyParameter is not a public key $this")
  } else {
    when (this) {
      is RSAKeyParameters -> WrappedRSAPublicKey(this)
      is DSAPublicKeyParameters -> WrappedDSAPublicKey(this)
      is ECPublicKeyParameters -> WrappedECPublicKey(this)
      else -> throw InvalidKeySpecException("Unsupported public key $this")
    }
  }
}

fun X509Certificate.asPublicKey(): PublicKey = this.publicKey

/**
 * Read PEM format file into [PemObject] and parse as [PublicKey].
 * @return [PublicKey]
 * @throws CertificateException certificate encode except.
 */
@Throws(CertificateException::class)
fun PemObject.asPublicKey(): PublicKey {
  val certificateFactory = CertificateFactory.getInstance(X509_ALGORITHM)
  val content: ByteArray = this.content
  val x509Certificate = certificateFactory.generateCertificate(ByteArrayInputStream(content)) as X509Certificate
  return x509Certificate.asPublicKey()
}

/**
 * convert to a private key from asymmetricKeyParameter
 */
fun AsymmetricKeyParameter.asPrivateKey(): PrivateKey {
  return if (!this.isPrivate) {
    throw InvalidKeySpecException("AsymmetricKeyParameter is not a private key $this")
  } else {
    when (this) {
      is RSAPrivateCrtKeyParameters -> WrappedRSAPrivateCrtKey(this)
      is DSAPrivateKeyParameters -> WrappedDSAPrivateKey(this)
      is ECPrivateKeyParameters -> WrappedECPrivateKey(this)
      else -> throw InvalidKeySpecException("Unsupported public key $this")
    }
  }
}

fun PrivateKey.asAsymmetricKeyParameter(): AsymmetricKeyParameter {
  return when (this) {
    is RSAPrivateCrtKey ->
      RSAPrivateCrtKeyParameters(
        this.modulus,
        this.publicExponent,
        this.privateExponent,
        this.primeP,
        this.primeQ,
        this.primeExponentP,
        this.primeExponentQ,
        this.crtCoefficient,
      )
    // pkcs8
    is RSAPrivateKey -> RSAKeyParameters(true, this.modulus, this.privateExponent)
    is DSAPrivateKey -> DSAUtil.generatePrivateKeyParameter(this)
    is ECPrivateKey -> ECUtil.generatePrivateKeyParameter(this)
    else -> throw InvalidKeySpecException("Unknown key ${this.javaClass.name}")
  }
}

/**
 * Also the same with [org.bouncycastle.x509.X509Util.getSignatureInstance].
 * @param issuerCert issuer cert
 * @return [SignatureAndHashAlgorithm]
 * @throws IOException ioException
 */
@Throws(IOException::class)
fun getCertSigAndHashAlg(
  subjectCert: TlsCertificate,
  issuerCert: TlsCertificate,
): SignatureAndHashAlgorithm? {
  val sigAlgOid = subjectCert.sigAlgOID
  var signatureAndHashAlgorithm: SignatureAndHashAlgorithm? = null
  if (sigAlgOid != null) {
    // openssl(version > 1.1.1d) built-in algorithm name are RSA, RSA-PSS, EC, X25519, X448, ED25519 and ED448
    if (PKCSObjectIdentifiers.id_RSASSA_PSS.id != sigAlgOid) {
      return cert_sig_alg_oids[sigAlgOid]
    }
    // OAEPParameterSpec
    val sigAlgParams = subjectCert.sigAlgParams
    val pssParams = RSASSAPSSparams.getInstance(sigAlgParams)
    if (pssParams != null) {
      signatureAndHashAlgorithm = getSignatureAndHashAlgorithm(issuerCert, pssParams)
    }
  }
  return signatureAndHashAlgorithm
}

/**
 * Read RSA PSSParams signature and hash algorithm.
 * @param issuerCert issuer cert
 * @param pssParams pass params
 * @return [SignatureAndHashAlgorithm]
 * @throws IOException ioException
 */
@Throws(IOException::class)
private fun getSignatureAndHashAlgorithm(
  issuerCert: TlsCertificate,
  pssParams: RSASSAPSSparams,
): SignatureAndHashAlgorithm {
  val hashOid = pssParams.hashAlgorithm.algorithm
  when (hashOid) {
    NISTObjectIdentifiers.id_sha256 -> {
      if (issuerCert.supportsSignatureAlgorithmCA(SignatureAlgorithm.rsa_pss_pss_sha256)) {
        return SignatureAndHashAlgorithm.rsa_pss_pss_sha256
      } else if (issuerCert.supportsSignatureAlgorithmCA(
          SignatureAlgorithm.rsa_pss_rsae_sha256,
        )
      ) { // TLS 1.3 rsa_encryption
        // oaepwithsha-256andmgf1padding
        return SignatureAndHashAlgorithm.rsa_pss_rsae_sha256
      }
    }

    NISTObjectIdentifiers.id_sha384 -> {
      if (issuerCert.supportsSignatureAlgorithmCA(SignatureAlgorithm.rsa_pss_pss_sha384)) {
        return SignatureAndHashAlgorithm.rsa_pss_pss_sha384
      } else if (issuerCert.supportsSignatureAlgorithmCA(
          SignatureAlgorithm.rsa_pss_rsae_sha384,
        )
      ) { // TLS 1.3 rsa_encryption
        // oaepwithsha-256andmgf1padding
        return SignatureAndHashAlgorithm.rsa_pss_rsae_sha256
      }
    }

    NISTObjectIdentifiers.id_sha512 -> {
      if (issuerCert.supportsSignatureAlgorithmCA(SignatureAlgorithm.rsa_pss_pss_sha512)) {
        return SignatureAndHashAlgorithm.rsa_pss_pss_sha512
      } else if (issuerCert.supportsSignatureAlgorithmCA(
          SignatureAlgorithm.rsa_pss_rsae_sha512,
        )
      ) { // TLS 1.3 rsa_encryption
        // oaepwithsha-512andmgf1padding
        return SignatureAndHashAlgorithm.rsa_pss_rsae_sha512
      }
    }

    else -> throw CertIOException("sha1 and sha224 with padding is not security any more.")
  }
  throw CertIOException("fail to recognize rsa pss params.")
}

/**
 * Check whether the issued certificate expired.
 * @param certificate [Certificate]
 */
@Throws(CertificateNotYetValidException::class, CertificateException::class)
fun verifyIssuedExpired(certificate: Certificate) {
  certificate.asX509s().forEach {
    verifyIssuedExpired(it)
  }
}

@Throws(CertificateNotYetValidException::class, CertificateException::class)
fun verifyIssuedExpired(x509Certificate: X509Certificate) {
  x509Certificate.checkValidity()
}

/**
 * Exchange handshake verify.
 * @param a local certificate
 * @param b remote certificate
 * @return bool
 * @throws IOException encode read
 */
@Throws(IOException::class)
fun verifyExchangeCertificate(
  a: Certificate,
  b: Certificate,
): Boolean {
  a.certificateEntryList.forEach { local ->
    b.certificateEntryList.forEach { remote ->
      if (isSameCertificate(local.certificate, remote.certificate)) {
        return true
      }
    }
  }
  return false
}

@Throws(IOException::class)
fun isSameCertificate(
  a: TlsCertificate,
  b: TlsCertificate,
): Boolean {
  return org.bouncycastle.util.Arrays.areEqual(a.encoded, b.encoded)
}

/**
 * Certificate entries chain verify.
 * @param certificate [Certificate]
 * @throws CertificateException certificate read except.
 * @throws NoSuchAlgorithmException algorithm except.
 * @throws SignatureException signature except.
 * @throws InvalidKeySpecException key except.
 * @throws NoSuchProviderException provider except.
 */
@Throws(
  CertificateException::class,
  NoSuchAlgorithmException::class,
  SignatureException::class,
  InvalidKeySpecException::class,
  NoSuchProviderException::class,
)
fun verifyCertificateChain(certificate: Certificate) {
  val chain = certificate.asX509s()
  for (idx in 0..<(chain.size - 1)) {
    chain[idx].verify(chain[idx + 1].publicKey)
  }
}

/**
 * Assign issued Certificate verify.
 * @param issuerCert [Certificate]
 * @param rootCert [Certificate]
 * @return bool
 * @throws IOException encode read
 */
@Throws(IOException::class)
fun verifyIssuedCertAssignFrom(
  issuerCert: Certificate,
  rootCert: Certificate,
): Boolean {
  issuerCert.certificateEntryList.forEach { issuedEntry ->
    rootCert.certificateEntryList.forEach { trustedCa ->
      if (isSameIssuer(issuedEntry.certificate, trustedCa.certificate)) {
        return true
      }
    }
  }
  return false
}

/**
 * Exchange TLS certificate verify.
 *
 * @param a local
 * @param b root
 * @return bool
 * @throws IOException encode read
 */
@Throws(IOException::class)
fun isSameIssuer(
  a: TlsCertificate,
  b: TlsCertificate,
): Boolean {
  val issuedHolder = X509CertificateHolder(a.encoded)
  val rootHolder = X509CertificateHolder(b.encoded)
  return issuedHolder.issuer == rootHolder.issuer
}

private fun addCertSigAlgOid(
  h: Hashtable<String, SignatureAndHashAlgorithm>,
  oid: ASN1ObjectIdentifier,
  hashAlgorithm: Short,
  signatureAlgorithm: Short,
) {
  addCertSigAlgOid(h, oid, SignatureAndHashAlgorithm.getInstance(hashAlgorithm, signatureAlgorithm))
}

private fun addCertSigAlgOid(
  h: Hashtable<String, SignatureAndHashAlgorithm>,
  oid: ASN1ObjectIdentifier,
  sigAndHash: SignatureAndHashAlgorithm,
) {
  h[oid.id] = sigAndHash
}

// ///////////////////////////////////////////////////////////////////////////

fun getContentType(
  buf: ByteArray,
  offset: Int = 0,
): String = ContentType.getName(TlsUtils.readUint8(buf, offset))

fun getContentDescription(
  buf: ByteArray,
  offset: Int = 0,
): String = ContentType.getText(TlsUtils.readUint8(buf, offset))

fun getHandshakeType(buf: ByteArray): String = HandshakeType.getName(TlsUtils.readUint8(buf, 13))

// ///////////////////////////////////////////////////////////////////////////
