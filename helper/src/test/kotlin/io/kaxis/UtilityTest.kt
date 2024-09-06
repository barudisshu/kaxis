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

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.generators.DHKeyPairGenerator
import org.bouncycastle.crypto.generators.DSAParametersGenerator
import org.bouncycastle.crypto.params.*
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory
import org.bouncycastle.math.ec.ECConstants
import org.bouncycastle.math.ec.ECCurve
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.PKCSException
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import org.bouncycastle.util.encoders.Base64
import org.bouncycastle.util.encoders.Hex
import org.bouncycastle.util.io.pem.PemObject
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.core.Is.isA
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.StringReader
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPrivateKeySpec
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

internal class UtilityTest {
  @Test
  fun getKeyFactoryTest() {
    assertThrows<NoSuchAlgorithmException> { getKeyFactory("AES") }
    assertNotNull(getKeyFactory(RSA))
  }

  @Test
  fun subjectPublicKeyInfoAsPublicKeyTest() {
    val rsaPkInfo = createSubjectPublicKeyInfo(RSA, "SHA256withRSA")
    assertThat(rsaPkInfo.asPublicKey(), isA(PublicKey::class.java))
    val dsaPkInfo = createSubjectPublicKeyInfo(DSA, "SHA256withDSA")
    assertThat(dsaPkInfo.asPublicKey(), isA(PublicKey::class.java))
    val ecPkInfo = createSubjectPublicKeyInfo(ECDSA, "SHA256withECDSA")
    assertThat(ecPkInfo.asPublicKey(), isA(PublicKey::class.java))
    val unSupportPkInfo = createSubjectPublicKeyInfo("Ed25519", "Ed25519")
    assertThrows<InvalidKeySpecException> { unSupportPkInfo.asPublicKey() }
  }

  @Test
  fun asymmetricKeyParameterAsPublicKeyTest() {
    // RDA
    val mod =
      BigInteger(
        """
        b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5
        """.trimIndent(),
        16,
      )
    val pubExp = BigInteger("11", 16)
    val rsaKeyParameters = RSAKeyParameters(false, mod, pubExp)
    assertEquals(RSA, rsaKeyParameters.asPublicKey().algorithm)

    // DSA
    val p =
      BigInteger(
        """
        F56C2A7D366E3EBDEAA1891FD2A0D099436438A673FED4D75F594959CFFEBCA7BE0FC72E4FE67D91D801CBA0693AC4ED9E411B41D19E2FD1699C4390AD27D94C69C0B143F1DC88932CFE2310C886412047BD9B1C7A67F8A25909132627F51A0C866877E672E555342BDF9355347DBD43B47156B2C20BAD9D2B071BC2FDCF9757F75C168C5D9FC43131BE162A0756D1BDEC2CA0EB0E3B018A8B38D3EF2487782AEB9FBF99D8B30499C55E4F61E5C7DCEE2A2BB55BD7F75FCDF00E48F2E8356BDB59D86114028F67B8E07B127744778AFF1CF1399A4D679D92FDE7D941C5C85C5D7BFF91BA69F9489D531D1EBFA727CFDA651390F8021719FA9F7216CEB177BD75
        """.trimIndent(),
        16,
      )
    val q = BigInteger("C24ED361870B61E0D367F008F99F8A1F75525889C89DB1B673C45AF5867CB467", 16)
    val g =
      BigInteger(
        """
        8DC6CC814CAE4A1C05A3E186A6FE27EABA8CDB133FDCE14A963A92E809790CBA096EAA26140550C129FA2B98C16E84236AA33BF919CD6F587E048C52666576DB6E925C6CBE9B9EC5C16020F9A44C9F1C8F7A8E611C1F6EC2513EA6AA0B8D0F72FED73CA37DF240DB57BBB27431D618697B9E771B0B301D5DF05955425061A30DC6D33BB6D2A32BD0A75A0A71D2184F506372ABF84A56AEEEA8EB693BF29A640345FA1298A16E85421B2208D00068A5A42915F82CF0B858C8FA39D43D704B6927E0B2F916304E86FB6A1B487F07D8139E428BB096C6D67A76EC0B8D4EF274B8A2CF556D279AD267CCEF5AF477AFED029F485B5597739F5D0240F67C2D948A6279
        """.trimIndent(),
        16,
      )
    val dsaParams = DSAParameters(p, q, g)
    val y =
      BigInteger(
        """
        2828003D7C747199143C370FDD07A2861524514ACC57F63F80C38C2087C6B795B62DE1C224BF8D1D1424E60CE3F5AE3F76C754A2464AF292286D873A7A30B7EACBBC75AAFDE7191D9157598CDB0B60E0C5AA3F6EBE425500C611957DBF5ED35490714A42811FDCDEB19AF2AB30BEADFF2907931CEE7F3B55532CFFAEB371F84F01347630EB227A419B1F3F558BC8A509D64A765D8987D493B007C4412C297CAF41566E26FAEE475137EC781A0DC088A26C8804A98C23140E7C936281864B99571EE95C416AA38CEEBB41FDBFF1EB1D1DC97B63CE1355257627C8B0FD840DDB20ED35BE92F08C49AEA5613957D7E5C7A6D5A5834B4CB069E0831753ECF65BA02B
        """.trimIndent(),
        16,
      )
    val dsaPublicKeyParameters = DSAPublicKeyParameters(y, dsaParams)
    assertEquals(DSA, dsaPublicKeyParameters.asPublicKey().algorithm)

    // ECDSA
    val n = BigInteger("6277101735386680763835789423176059013767194773182842284081")
    val curve =
      ECCurve.Fp(
        BigInteger("6277101735386680763835789423207666416083908700390324961279"),
        BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
        BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16),
        n,
        ECConstants.ONE,
      )
    val ecDomainParameters =
      ECDomainParameters(curve, curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), n)
    val ecdsaPublicKeyParameters =
      ECPublicKeyParameters(
        curve.decodePoint(Hex.decode("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5")),
        ecDomainParameters,
      )
    assertEquals(ECDSA, ecdsaPublicKeyParameters.asPublicKey().algorithm)

    // wrong public key
    val g512 =
      BigInteger(
        """
        153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc
        """.trimIndent(),
        16,
      )
    val p512 =
      BigInteger(
        """
        9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b
        """.trimIndent(),
        16,
      )
    val dhParams = DHParameters(p512, g512)
    val dhKeyGenParams = DHKeyGenerationParameters(SecureRandom(), dhParams)
    val dhKpGen = DHKeyPairGenerator()
    dhKpGen.init(dhKeyGenParams)
    val keyPair = dhKpGen.generateKeyPair()
    val dhPubParams = keyPair.public
    assertThrows<InvalidKeySpecException> { dhPubParams.asPublicKey() }
  }

  @Test
  fun asymmetricKeyParameterAsPrivateKeyTest() {
    // RSA
    val mod =
      BigInteger(
        """
        b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5
        """.trimIndent(),
        16,
      )
    val pubExp = BigInteger("11", 16)
    val privExp =
      BigInteger(
        """
        92e08f83cc9920746989ca5034dcb384a094fb9c5a6288fcc4304424ab8f56388f72652d8fafc65a4b9020896f2cde297080f2a540e7b7ce5af0b3446e1258d1dd7f245cf54124b4c6e17da21b90a0ebd22605e6f45c9f136d7a13eaac1c0f7487de8bd6d924972408ebb58af71e76fd7b012a8d0e165f3ae2e5077a8648e619
        """.trimIndent(),
        16,
      )
    val p =
      BigInteger(
        """
        f75e80839b9b9379f1cf1128f321639757dba514642c206bbbd99f9a4846208b3e93fbbe5e0527cc59b1d4b929d9555853004c7c8b30ee6a213c3d1bb7415d03
        """.trimIndent(),
        16,
      )
    val q =
      BigInteger(
        """
        b892d9ebdbfc37e397256dd8a5d3123534d1f03726284743ddc6be3a709edb696fc40c7d902ed804c6eee730eee3d5b20bf6bd8d87a296813c87d3b3cc9d7947
        """.trimIndent(),
        16,
      )
    val pExp =
      BigInteger(
        """
        1d1a2d3ca8e52068b3094d501c9a842fec37f54db16e9a67070a8b3f53cc03d4257ad252a1a640eadd603724d7bf3737914b544ae332eedf4f34436cac25ceb5
        """.trimIndent(),
        16,
      )
    val qExp =
      BigInteger(
        """
        6c929e4e81672fef49d9c825163fec97c4b7ba7acb26c0824638ac22605d7201c94625770984f78a56e6e25904fe7db407099cad9b14588841b94f5ab498dded
        """.trimIndent(),
        16,
      )
    val crtCoef =
      BigInteger(
        """
        dae7651ee69ad1d081ec5e7188ae126f6004ff39556bde90e0b870962fa7b926d070686d8244fe5a9aa709a95686a104614834b0ada4b10f53197a5cb4c97339
        """.trimIndent(),
        16,
      )
    val rsaPrivateCrtKeyParameters = RSAPrivateCrtKeyParameters(mod, pubExp, privExp, p, q, pExp, qExp, crtCoef)
    assertEquals(RSA, rsaPrivateCrtKeyParameters.asPrivateKey().algorithm)

    // DSA
    val rootSerialNum = BigInteger(SecureRandom().nextLong().toString())
    val seed = Hex.decode("ED8BEE8D1CB89229D2903CBF0E51EE7377F48698")
    val pGen = DSAParametersGenerator()
    pGen.init(DSAParameterGenerationParameters(1024, 160, 80, SecureRandom(seed)))
    val dsaParameters = pGen.generateParameters()
    val dsaPrivateKeyParameters = DSAPrivateKeyParameters(rootSerialNum, dsaParameters)
    assertEquals(DSA, dsaPrivateKeyParameters.asPrivateKey().algorithm)

    // ECDSA
    val n = BigInteger("6277101735386680763835789423176059013767194773182842284081")
    val curve =
      ECCurve.Fp(
        BigInteger("6277101735386680763835789423207666416083908700390324961279"),
        BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
        BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16),
        n,
        ECConstants.ONE,
      )
    val params =
      ECDomainParameters(curve, curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), n)
    val ecdsaPrivateKeyParameters =
      ECPrivateKeyParameters(BigInteger("651056770906015076056810763456358567190100156695615665659"), params)
    assertEquals(ECDSA, ecdsaPrivateKeyParameters.asPrivateKey().algorithm)

    // Only support RSA/DSA/ECDSA
    // HD
    val g512 =
      BigInteger(
        """
        153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc
        """.trimIndent(),
        16,
      )
    val p512 =
      BigInteger(
        """
        9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b
        """.trimIndent(),
        16,
      )
    val dhParams = DHParameters(p512, g512)
    val dhKeyGenerationParams = DHKeyGenerationParameters(SecureRandom(), dhParams)
    val kpGen = DHKeyPairGenerator()
    kpGen.init(dhKeyGenerationParams)
    val dhPair = kpGen.generateKeyPair()
    val dhPrivateKeyParameters = dhPair.private
    assertThrows<InvalidKeySpecException> { dhPrivateKeyParameters.asPrivateKey() }

    // Wrong Key
    val wrongMod =
      BigInteger(
        """
        b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5
        """.trimIndent(),
        16,
      )
    val wrongPubExp = BigInteger("11", 16)
    val rsaKeyParameters = RSAKeyParameters(false, wrongMod, wrongPubExp)
    assertThrows<InvalidKeySpecException> { rsaKeyParameters.asPrivateKey() }
  }

  @Suppress("ktlint:standard:max-line-length")
  @Test
  fun privateAsAsymmetricKeyParameterTest() {
    // RSA
    val rsaPrivateKey = createPrivateKey(RSA)
    assertTrue { rsaPrivateKey.asAsymmetricKeyParameter().isPrivate }
    // DSA
    val dsaPrivateKey = createPrivateKey(DSA)
    assertTrue { dsaPrivateKey.asAsymmetricKeyParameter().isPrivate }
    // ECDSA
    val ecPrivateKey = createPrivateKey(ECDSA)
    assertTrue { ecPrivateKey.asAsymmetricKeyParameter().isPrivate }
    // unsupport
    val ed25519PrivateKey = createPrivateKey("Ed25519")
    assertThrows<InvalidKeySpecException> { ed25519PrivateKey.asAsymmetricKeyParameter() }
    // PKCS8
    val encPriv =
      Base64.decode(
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC1TpIe8iB2h4qb0K54qhH6LXcjhdkDOo9X5tp2dR2tOULOJM19sZ0RVJE+St01xDNh6CPrwrWAdhPvnl020oCqckfqTqhB8fTzcxPR5htOeLWx/fM05j42zjMjKbfMwEPlVDqnN9KT1JnKxuiGF4SQwsuDoJirjHWzGexLV9rtfaa5spebGhqbm3STO1c8jS/sTqJhZh+Igi8SKvrjbXN9+TSDLOd8s0/UdZKm1w6A01tEXIa8+HxkXLCug0BPB9AVMRnql/cXDt4yUw3R4OO9WJv2/aIQvYNINnE4dib2Q8XYRMm5FGgSrolbYApKzfJ5N/y5sRme56ohRbqUoUR3AgMBAAECggEAFV6j6WLXgbD7HN9tWQqOoOKv+q9hgzhpQc6TbEfkjhDEN4Dt+YUwQqUpk2KGjTpJZh5S8YxbET+ZnPIZAYexI6XhpRPNUCyBFxq2uNQ63rZqkAajHlaO+a23KEtX/xmgRwz09tWlC8iQse5c5MUr2lYjX6nTpNCi5M/G4qCBzOEByjxkKCXbgaTKsgLb7ax2CoC3BUbWjQnbQ2V9tRImBX92b1NF0ER0Xovy7VH0rwrQnTEkD8U6OrRs+UAX+zCzkV69BJPou47s4jSdDksy5vhteVdx+HnucEeLgpJoqixiDWofZvX7+NAsGs+e74bV/vQinuY6a1ILEH3g1+rhGQKBgQD1J7sUdmbXelGUys5rERdYP9xTNuyqV38DrgPDyE8pgpwrvM5gn1cRb8Wop6xOp/vVME8Fu9PE65+T5nRb8zEvypi+4mGsjksI7ZsQ4VqV7G1GfTT8QKjr+gEk7t+jN2ymL6lp2x+bbSHQniPP51FDl72RsKY0Pk4Iy9aMKbxXHwKBgQC9U8mqMveT8e+ztiVwUdM2AvQSv+WNyVD5q78db5mrxur20b8UU7cyDFJoH6Y72GT/sKuL4LSAD8ZrUg5rnZWtXP63WnAlRJaMI0d7McV7OwsaByJVlI/Yq3OpC8x1+Pf1jy6HJzxFVmMMllYi63CzqPwIAgnGdHP4C/p/CmEfqQKBgG6ip4LsjCziPr7vZ4haBjcFWuETAGs/YUq/1WMdmtwY3XG/m0NvpVNxJbqfMNuuY7AqRP9JbKCJ1VJhxlFYxvHSdGxwrbO545L75+cOTFssf4Q4LRlJ9PHJuYp5YuO9t4KoL8Rd5z21WnVTaMYClmHysNJ27grVs1G06/YFP8HxAoGAKvFjT5CJ6Wu58+g/q69Tme+njs0p8zQTgt361mFm2LiguOUwUxr99YMn+egb230kw34+GtcX+egaGGOfU7eFqLHsMIh54WoiP50M7JuIcIAe74NovUKaMgoJjPFZKfUTwQX+BrfWit+iTcuXtAn1ITsWF3bm4rWtTDjjU4d2KikCgYEA7Zwj/hGL7pmbDjfBK0aG+06JPQ1LHYVXHOUxco9eB1sgJXoxBjqoJPU0j7NCrn6i3tiDtLPYNAO9ehaRLucFk8FjthrewHmZY+x+nmzkEbMbi1kDTIvY4pw5jn9k5CEBAe2MSymjzfPTWV2YhuG1Lu5ibSQ+LMMbUppniD9N2pA=",
      )
    val keyFact = getKeyFactory(RSA)
    val priv = keyFact.generatePrivate(PKCS8EncodedKeySpec(encPriv))
    if (priv is RSAPrivateKey) {
      val privateKey =
        keyFact.generatePrivate(
          RSAPrivateKeySpec(
            priv.modulus,
            priv.privateExponent,
          ),
        )
      assertTrue { privateKey.asAsymmetricKeyParameter().isPrivate }
    }
  }

  @Test
  fun publicKeyAsAsymmetricKeyParameterTest() {
    // RSA
    val rsaPublicKey = createPublicKey(RSA)
    assertFalse { rsaPublicKey.asAsymmetricKeyParameter().isPrivate }
    // DSA
    val dsaPublicKey = createPublicKey(DSA)
    assertFalse { dsaPublicKey.asAsymmetricKeyParameter().isPrivate }
    // ECDSA
    val ecPublicKey = createPublicKey(ECDSA)
    assertFalse { ecPublicKey.asAsymmetricKeyParameter().isPrivate }
    // unsupport
    // DH
    val dhPublicKey = createPublicKey("DH")
    assertThrows<InvalidKeySpecException> { dhPublicKey.asAsymmetricKeyParameter() }
  }

  @Test
  fun `Certificate ASN1 X509 PublicKey`() {
    val content =
      """
        |-----BEGIN CERTIFICATE-----
        |MIIDDTCCAnagAwIBAgIJANQN5U6iXqI1MA0GCSqGSIb3DQEBCwUAMIGcMQswCQYD
        |VQQGEwJjbjESMBAGA1UECAwJR3Vhbmdkb25nMRIwEAYDVQQHDAlHdWFuZ3pob3Ux
        |FzAVBgNVBAoMDkVyaWNzc29uLCBJbmMuMQ8wDQYDVQQLDAZjcGxpZXIxFTATBgNV
        |BAMMDGVyaWNzc29uLmNvbTEkMCIGCSqGSIb3DQEJARYVZ2FsdWRpc3VAZXJpY3Nz
        |b24uY29tMCAXDTIxMDcxNTA5MjU0OFoYDzMwMjAxMTE1MDkyNTQ4WjCBnDELMAkG
        |A1UEBhMCY24xEjAQBgNVBAgMCUd1YW5nZG9uZzESMBAGA1UEBwwJR3Vhbmd6aG91
        |MRcwFQYDVQQKDA5Fcmljc3NvbiwgSW5jLjEPMA0GA1UECwwGY3BsaWVyMRUwEwYD
        |VQQDDAxlcmljc3Nvbi5jb20xJDAiBgkqhkiG9w0BCQEWFWdhbHVkaXN1QGVyaWNz
        |c29uLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA6wJfZ5LSSrpYSmxC
        |2gAkjiurunpc5txaHxMq2l9JSg4pfT+O0Jmv948WlJZqq9JMIFtrNcCUl2jXjapB
        |w2eGSST9DjVTV0oX4ez/6bXnItGsJhKJ5dWHk+3ORpu9VR1Tcykg1GGCTqD7vkq7
        |ngnhfsgo95EEF9p2frqYW4lImFUCAwEAAaNTMFEwHQYDVR0OBBYEFNGUrbAo75iA
        |XeXkG+J/Eq7vovUYMB8GA1UdIwQYMBaAFNGUrbAo75iAXeXkG+J/Eq7vovUYMA8G
        |A1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAzQamyrVISKfLM0S94lmd
        |jC/gqmpzfXMo+BaFGSujmZA/ifXqlMHjC0dzdeV4QCVdpfRw8lA6LX8yCEV0Z5AF
        |A+1CmPk4ERfn4JElz+o/TXTTTWVgbDU4whV5YtB73P2/k+Nn6mTPydml+any6x/V
        |G59TYIBiSB906gWe67rvAv4=
        |-----END CERTIFICATE-----
        |
      """.trimMargin()
    val x509 = CertificateFactory().engineGenerateCertificates(ByteArrayInputStream(content.toByteArray()))
    if (x509 is ArrayList) {
      val x509s = x509.map { it as X509Certificate }
      val crypto = BcTlsCrypto(SecureRandom())
      val certificate = x509s.asCertificate(crypto)

      assertThat(certificate, isA(org.bouncycastle.tls.Certificate::class.java))
      assertEquals(x509s, certificate.asX509s())

      val asn1s = certificate.asAsn1s()
      assertThat(asn1s[0], isA(org.bouncycastle.asn1.x509.Certificate::class.java))

      val publicKey = asn1s[0].asPublicKey()
      assertThat(publicKey, isA(PublicKey::class.java))
    }
  }

  @Test
  fun `PemObject as AsymmetricKeyParameter`() {
    val rsaContent =
      """
        |-----BEGIN RSA PRIVATE KEY-----
        |MIICXAIBAAKBgQC2E2WqvTUFNoS89x+ZPtuk73DW1CLPZZVi8d+3uvf58CVDadE6
        |5MDVMvyXV8uYrwPhO573PlOZyJL5llwntb3V0VPZtTj8i21lUPakgIU3DfyyCBLZ
        |b10nrJFmBSTs5O2ohIaM1P3sDYeG3ZjejQYmB6dqUmp8WqX8pA7xusqmhwIDAQAB
        |AoGAJWzhRfI0Vsj5CdqGDTrlbQamnBHowdawmTD8ekidNivNjQjQMBnbJTegwf8S
        |42R+GKrnpwyRpJec1l64vJTX2yVXR3uon6HJ8Br5xVBluo4KlU4jd0dgGeLjPXpV
        |tUjgTqeKegimwhiyF6cctgCfI9e1KdtcIy7RDnFXc697HcECQQDsd/m8Tr5GXndO
        |9gFcMdHdS+y0Y1tknxUU2SHnkxbrKwGmCfv5UpBigo0jjJGQCWP4otXNbflehZkn
        |NdwtIg3nAkEAxR1O6ug+CKwmaabIKHfAG9Jc6AiOH0dBiD+Q6vpiBb2RVzcTvBbK
        |kMWIw60SEfb9tuWwMrM5BePRka2aX0FOYQJBAISocePgUQJtMIWNoQm1sURyuaIh
        |Mz5puIvvnAOsEulvQQeDBmbCmNmK398Xlvm1Ku5re4I5tfH/BQJoRtLTDfUCQHvn
        |jHAFRNlWvV60RCWMAOp8NYJ1vkDTHdJzgrjyYyOQogfcyz70ZKjUQsAdzroUNC//
        |+d4k4rddGaMlKWCvQIECQCjBTbFvcMIp76Ano/CN6awzXWbq5jOiNw0S5GYwho5M
        |ujwwhk/KnwTHQW8+g60lhNXCU2V3x9cjgDYZn7ULHtY=
        |-----END RSA PRIVATE KEY-----
        |
      """.trimMargin()
    val rsaPemObject = loadPemContent(rsaContent)
    assertTrue { rsaPemObject.asAsymmetricKeyParameter().isPrivate }
    assertTrue { rsaPemObject.asAsymmetricKeyParameter("P@ssw0rd").isPrivate }

    val pkcs8Content =
      """
        |-----BEGIN PRIVATE KEY-----
        |MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBALc/VEO9xwkdSIdt
        |wkg4QJBljFE9htVTTu0L+eXbptx+R+UHH6dPTkJSmOnUIXF4hn8ZpFLkoYNTL3/i
        |MGrozXFqoRa/OeDKt8sxLrsCnKQqevLQebQ9I1IlCECs66diXh39abhq+wG/iepA
        |uvtvMA1X9GIAXDjCTUJrrvxk9iRJAgMBAAECgYAd8Mb/2n4uyw4SsqhPzIEgFrd6
        |fqcNK/N1X8OQ/vagiDGPBj7xw09yHrTFX9enBp5THglvUdPh9TGJn5dxoGAQpR+f
        |ij4cfTLkKqDpuwoOUwHJxcp/EMqCxt+g0JDlNtHut+9DltTzLzgddLgOIwmOeBpY
        |Ji2Q4QtJk0M+FUXVUQJBAN9o3gSHkv6mxTf2yJvsy8BH7m3x2cBtD05K7CNbdUUd
        |W01SQkXHlGR2iWRy6/quqYkyS1x0IfB1IEuv0Y2e8MMCQQDR+p7RIUOtSePkoeVN
        |EDUN6giBy4njedVn2Pl+VW/NU8EEfCuyDNceLS6ilK/Y7HV1nLD5Qz8c6M5K6jE8
        |bEYDAkBd/mvycevZcebl7dFnMNBknJ7m6OsZd4kKAqGpGpCTPI+uT16MpzR6tBiI
        |B4XbGWNA0sU8J6wj09N7pIRA1k8rAkA7GBlSKdZuEnl8gsORqJoFzHOQc8PerQ8O
        |JtYwY8MPOh78MCXr+gkgiP6y6r2Cgymba/mybOZ6MFq+YqJwqtgZAkBCTAtzc1Zy
        |cHLS/rrzhsPoho84gZCteffE4Lzcs5WhqW245mQO4AlYUWLusZLdL0hG5pK8AllI
        |8GwzEsdNvavM
        |-----END PRIVATE KEY-----
        |
      """.trimMargin()

    val pkcs8PemObject = loadPemContent(pkcs8Content)
    assertTrue { pkcs8PemObject.asAsymmetricKeyParameter().isPrivate }

    // openssl genrsa -out ca.key -aes128 -passout pass:P@ssw0rd 1024
    val rsaEncryptContent =
      """
        |-----BEGIN RSA PRIVATE KEY-----
        |Proc-Type: 4,ENCRYPTED
        |DEK-Info: AES-128-CBC,392661B837964DB98C466ED6B092CA55
        |
        |alXROHP5tWe6KYmSv3sZfFLxUh/EtMcuf8LB4r0JJGS1Hbg7cSRPLY9XetmTk/nf
        |FjPwzmWZUf2mYGH6ql5w7WUoTzJ2W1itaZgirdNydi40+wGq70Z4dGT41sNahZ9x
        |XNEDFQAQPBHdQ0qGdU++muC5I8KRpWRCZcQanzOh/tmfqF0D47qzvUrAbfcGt3Qb
        |dQjB8wYQcCKLmCd3mk595kdZVQDILqN+xoX3rqJD1JBnvUgHrem/ngdpgASZd4kM
        |l5elVmicJFgbxdIykVNwT2WA2VCwtxxLgOi0vZIdekKLN4lccEy7THwmuAUjxeWa
        |TwZA/Q827MpHaycYfRvKox3EhjxtISvCY9E3iOQ85+LHXOc7qwJ6aKWE1cTN6lKo
        |EZD2wzSXRpswjxTlmdAImVTOodn2JBc+ltO6MNWSgGRsQojMBgc+Gr1SLovEsbuM
        |xegargVapHewLlOEO0pL7L308sm3x6hi/tOXrQ2Wh7aipUowEBTMIKxgU10Vu2L3
        |MvzICwzA1NS2mWnWvj5RKQedFsunKmd7pYNJhNwYP2VIeVR27IigSi0+Qlwe9n8j
        |klLbIFuwliRSezsCMjLK3+Pc01IywLuilBe6lkiBwnI1K1BSMM5B/hZhsgy76QV6
        |QlcsedkXsnTOC4bbmhSmygU+jwr0N0pYhap1uFmPHrgeB+C2ph7Ny5f25r3KhstR
        |vb/3twuWdaRypqUanJ02Flb46OOtBIhlMObNVqJ3gOzq4152vXCCxh3+rBmMav29
        |G5a3JzOEzcFomUFnSijK7U3Mg4OJDFqC/VJcd/WkWSwCBoouJLAydScB+pLZ8emJ
        |-----END RSA PRIVATE KEY-----
        |
      """.trimMargin()

    val rsaEncryptPemObject = loadPemContent(rsaEncryptContent)
    assertTrue { rsaEncryptPemObject.asAsymmetricKeyParameter("P@ssw0rd").isPrivate }

    val pkcs8EncryptContent =
      """
        |-----BEGIN ENCRYPTED PRIVATE KEY-----
        |MIIC3TBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI6T6YzPn438ECAggA
        |MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBw5rDy+syhWjH1bSr1wdpsBIIC
        |gNpW/bVkikKTmDOhtEUe1ipg+IxNMXJ9yUqWvUFu9OeAZw5AAHR/xfM3efV5aLhl
        |+D28gFaxSeL6ZipDX3MpM1VTc6/4NJgySce3TP1HKwSUBAL7c4q7KCsHQQ5yX3hh
        |gAHphmnQEPUEDhbPHRZbfvkyaJrv0jzSymLRaTagTa0a8iJoczcjnmf3NQWNe5YU
        |En/UPa4T3VMgqLDum7DgfmHPjfOwHYD4rdAZv/J/P6wTdBYyPulvW+lhvWftegu0
        |Xfj7V6TePbxIviU2IP/Yc5mJ+x4iS0V+JmlY2iYVav8mXBZTVgcPFp3/E3+u97DE
        |rlz5QPSad5hPG5fKyvDfULomQGQSmi2b54vYe2zsPZ7qudm0Q2d3Wbvg9utI3bPf
        |z4AGcKvuOWA+GFBU/7YtNF1pLFhalkZp4TMrPknrvO4mjg57CMihty5KspsYHu4d
        |DH/ielmFAQIhJKgD3ts1+nuNIYWFhSu+gNRw3weNd7p8PpcxDPGWpIIBdrz11uMG
        |UDalq7GNQYj+M8VXJXB2rpMym93GB+VGjsntjvh52i60sKY12PF5Z4e1dWhrVe9H
        |zr/mLDBivGdYyAWTEbXRnEWvZO6D+gOebKSSzbHAwpup+8AzSjeUihODckhRAwAO
        |vIL09E3AiGodBFmAlVrbOmR8fOX3BvdrTKa+Dy7GWCcQzpBX2T/J8fiFebMfBDzQ
        |iptSO9r+MzirW6lqRJ9bL/XGfOG4jYxuv2X/M/GhEgEzU0vNisTKTziLjM5ecx6N
        |7dHFX/cwbK36b+Q4u6+bIxfSeLG48IYFjEPkUVjekENw63ZPppza+/TaX/Qj+dDq
        |LoauUApjxGWwpjNHpwuYsV0=
        |-----END ENCRYPTED PRIVATE KEY-----
        |
      """.trimMargin()

    val pkcs8EncryptPemObject = loadPemContent(pkcs8EncryptContent)
    assertTrue { pkcs8EncryptPemObject.asAsymmetricKeyParameter("P@ssw0rd").isPrivate }
    assertThrows<PKCSException> { pkcs8EncryptPemObject.asAsymmetricKeyParameter("Hacked") }
    assertThrows<PKCSException> { pkcs8EncryptPemObject.asAsymmetricKeyParameter() }

    val dsaContent =
      """
        |-----BEGIN DSA PARAMETERS-----
        |MIIBHgKBgQDt3L0oJh8qL+kxEXtkI6M7yEvwlHas8BV2jRx2+pd2M3nqMP0Ixyre
        |LmyaaoQA3fKjfkBigTARNA+n5s6ds52OjP7yuE91ad6/uy+ULhlZF2Lem4TeKEiB
        |yZL+bw3ghAva2t1yM9ENtgaM7kH2YbHu+QO2reyiiVkNwar2xeflswIVAN9hiOuQ
        |Ytzd5IMZwswFy6Amop5fAoGASSCBySjEU112wIvjMUPnnxk2aDJ9cGhok7BZNjQ2
        |hm1DnqU3b+W+JlfZqjMsEFf7h5KoYTvJ7KI2WHIN9k+StQKLoszXmbhbeNy0GK3F
        |ShRdTlu2nWoo8UyYsjc5IVJJ6QBZ8WlMiYtbZ3LpMdpDHftgRVnV+IGlemHeDOuC
        |dk0=
        |-----END DSA PARAMETERS-----
        |-----BEGIN DSA PRIVATE KEY-----
        |MIIBvAIBAAKBgQDt3L0oJh8qL+kxEXtkI6M7yEvwlHas8BV2jRx2+pd2M3nqMP0I
        |xyreLmyaaoQA3fKjfkBigTARNA+n5s6ds52OjP7yuE91ad6/uy+ULhlZF2Lem4Te
        |KEiByZL+bw3ghAva2t1yM9ENtgaM7kH2YbHu+QO2reyiiVkNwar2xeflswIVAN9h
        |iOuQYtzd5IMZwswFy6Amop5fAoGASSCBySjEU112wIvjMUPnnxk2aDJ9cGhok7BZ
        |NjQ2hm1DnqU3b+W+JlfZqjMsEFf7h5KoYTvJ7KI2WHIN9k+StQKLoszXmbhbeNy0
        |GK3FShRdTlu2nWoo8UyYsjc5IVJJ6QBZ8WlMiYtbZ3LpMdpDHftgRVnV+IGlemHe
        |DOuCdk0CgYEAqmlpagzo5t1ss8F+r9hc1epRAXF6anEBNaQpJszMjCc4NN6vUvWi
        |wsy1H3HoPw/FiY//5S9PKgh3CJmzIrNBN1CCvHxxTIhl9FrJ1RPXZ8xewd/hOpQ9
        |vOslqp5YMLXhgGZf0fbyMyM8zmR6tNWTJOtnb30dLgAoExjky38VM2ECFQCT1Ghz
        |hbQClKNMLzIVF8Coh36Fmg==
        |-----END DSA PRIVATE KEY-----
        |
      """.trimMargin()

    val dsaPemObject = loadPemContent(dsaContent)
    assertTrue { dsaPemObject.asAsymmetricKeyParameter().isPrivate }

    // openssl dsaparam -genkey -out ca.key 1024
    val dsaEncryptContent =
      """
        |-----BEGIN DSA PRIVATE KEY-----
        |Proc-Type: 4,ENCRYPTED
        |DEK-Info: DES-EDE3-CBC,3768B9BC5C3542FE
        |
        |XlxhlhEEaaJap7uRleAmd6uM8vS3vHQd+bocSdjcBJoTR+7UF7GsUtbS1wMPXols
        |ydvrQcXOReyi1+sGGARR71GS8Jkt3s+ayiEp56Jvmk9QDSlna6K+yTyEmhf4+jTg
        |Lxuo+AOkFVVC0Xmor6r4rTrSiO+XjieK0bShOFZCQ617QPkvq+KhXqBNULX1KHHE
        |RzjsGf89BiTf7D4BjwLzzhe5NztkQsi00qwp9Nt2+GOqgzbNTJtNdXGwx2bNXQ0q
        |FFCr5nZV7W6cZ/8AvHXmZjulV87t0+wIInl1RBS3CbHExykQUEVjOAIniYNS/xP8
        |FpvtBnEWND95bDgZyTu7Cg38X5j5SR0ErZRyJQEgBzEBBfyZ5fkBjb46nc1ba9/u
        |tQYC0sjuRyGJNGC5egrIuM7jz8+cTDKBF8JXKaeM7kIAyB+H9TS8aKOv7W3KG1N1
        |ncPiLsW3zUEPIA9SzV2oHfXaNw+5YGDgHoR1pBArpIFh6/yYh3pCCYMC/lPxI6Yw
        |VNIjLWphvBQbH+9AyPYuALaqEZrpEiDmXYT0hT4CPBpbCw7mqQ59QYQ8A8LG0qj+
        |eiVvVl2dCaDLjDtyS80o6Rnr1y1N9ymJMVgIYRpFlcyQbdfcrzVj6vgAuGPt4PYs
        |qZhTcT801hWwH5UTucs5wnE2GivCjWQBVxCJHPQQL0wnhnMrNudW3eNcPq13vuV1
        |SD6F5JIh8YKQi8kYQNaYG/FdiFdtcLUJbhwgeHu6MU8RzjJweR+Zv+iyXZ5EV43p
        |xczM20wmywUGtiqCEwG+U7gW9PFcoM3mIO7MwgxGMqLU5QVWH++OhAGXyml6Q07X
        |Zpieu6ofAKoB+NmUFBnTioLIxURS0iBB0FgD+TcyViYWwCabJkWUwIZTS+4AyuxL
        |AIn/natGt/q7Uo3L4zjwdh6x7xsSMdnBRxda+Mmw/As8frZcM8q2sWNmml2zt6EF
        |KcrbfokH032yLPSkyWFaYXCnGItFiCchZfPpIJEZutc4K+ZjLVCsWrN0yC+T2GRz
        |gAoJ4rFMnENZ3+vOCNNZ3pI8HTlxYIW6JbByKoPS2oxZFt97XlUfQt8JjvMPduwd
        |A9anmaIFcdDDS6e15r9rt6nhi4G+w0XisYP8u1KJtPy/bATZ9mRGZDpYeFhm3CwG
        |-----END DSA PRIVATE KEY-----
        |
      """.trimMargin()
    val dsaEncryptedPemObject = loadPemContent(dsaEncryptContent)
    assertTrue { dsaEncryptedPemObject.asAsymmetricKeyParameter("P@ssw0rd").isPrivate }

    // openssl ecparam -genkey -name secp384r1 -noout -out ca.key
    val ecContent =
      """
        |-----BEGIN EC PRIVATE KEY-----
        |MIGkAgEBBDDFa2kKwIrYjDg5pxlNiu9mJdrjrB0P88G+07pf76SwRka5VeptIHOb
        |Z5/HpKC3oM+gBwYFK4EEACKhZANiAAT00BauqCFjG3QbjfvqqfPM57ARDp0AoiEK
        |b2yTszVcykxKnuTpbmuagNbdBEFfGmj+tDuC7KvUX+udzWnK1E+X6YmsV101XAgE
        |LEAXmoxNc6fjNWt9e0ATHi8JKoXi2ZI=
        |-----END EC PRIVATE KEY-----
        |
      """.trimMargin()

    val ecPemObject = loadPemContent(ecContent)
    assertTrue { ecPemObject.asAsymmetricKeyParameter().isPrivate }

    // openssl ecparam -name P-256 -genkey
    val ecParamContent =
      """
        |-----BEGIN EC PARAMETERS-----
        |BggqhkjOPQMBBw==
        |-----END EC PARAMETERS-----
        |-----BEGIN EC PRIVATE KEY-----
        |MHcCAQEEIDoCgw4bn4RhP3BIAhEC6522RCyIhakmeud0Z3bSHmDfoAoGCCqGSM49
        |AwEHoUQDQgAEL2eF736uNrjNM353IABVOiqyuOA5ePTTKueEhxf+sjHWBBKXwwKw
        |T3KV7rxpEoDc/HX6Us3Bid1liQeJrfs6ug==
        |-----END EC PRIVATE KEY-----

      """.trimMargin()
    val ecParamPemObjects = loadPemContent(ecParamContent)
    assertTrue { ecParamPemObjects.asAsymmetricKeyParameter().isPrivate }

    val ecEncryptContent =
      """
        |-----BEGIN EC PRIVATE KEY-----
        |Proc-Type: 4,ENCRYPTED
        |DEK-Info: AES-192-CBC,E00060D66ACA657A8D376C6DD1A76283
        |
        |QklG67rEFYpJswoGiqdISfk61KXNK2KBNaS1ftOi+Zg2ona0AqLcPTR+K5YXwknm
        |vfvJbZDyRrMYkKKGVkTmh/3Zo5b6gn3DYV1XwVaLQNWoLkJSGEbtFylUIdD0aBZY
        |7vGCPtZZjd+OKvoJcQfEqKlGVD0Yyq/CXBSrQvTclkg=
        |-----END EC PRIVATE KEY-----

      """.trimMargin()
    val ecEncryptPemObjects = loadPemContent(ecEncryptContent)
    assertTrue { ecEncryptPemObjects.asAsymmetricKeyParameter("P@ssw0rd").isPrivate }

    val x509Content =
      """
        |-----BEGIN CERTIFICATE-----
        |MIIEFjCCAv6gAwIBAgIJAKgxIwV0NU0nMA0GCSqGSIb3DQEBCwUAMIGeMQswCQYD
        |VQQGEwJjbjESMBAGA1UECAwJR3Vhbmdkb25nMRIwEAYDVQQHDAlHdWFuZ3pob3Ux
        |FzAVBgNVBAoMDkVyaWNzc29uLCBJbmMuMREwDwYDVQQLDAhlcmljc3NvbjEVMBMG
        |A1UEAwwMZXJpY3Nzb24uY29tMSQwIgYJKoZIhvcNAQkBFhVnYWx1ZGlzdUBlcmlj
        |c3Nvbi5jb20wIBcNMjEwNzEyMDI0NzM1WhgPMzAyMDExMTIwMjQ3MzVaMIGeMQsw
        |CQYDVQQGEwJjbjESMBAGA1UECAwJR3Vhbmdkb25nMRIwEAYDVQQHDAlHdWFuZ3po
        |b3UxFzAVBgNVBAoMDkVyaWNzc29uLCBJbmMuMREwDwYDVQQLDAhlcmljc3NvbjEV
        |MBMGA1UEAwwMZXJpY3Nzb24uY29tMSQwIgYJKoZIhvcNAQkBFhVnYWx1ZGlzdUBl
        |cmljc3Nvbi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDdT7et
        |D1Dhv8bfQvnjGMpEtDnl70Wv7rfrFjxRM99rKd0WrPlCtXRuzGYpEBTqdoQHRaMn
        |FAerHVHrwFBIxgaHNcgb6wv6Xk7Zebgq4loQiQU2UO+L8TWKqB5yRBzi68v90E3z
        |+8Kigi99XIldtkCcOkYs34np4uHM8jMLGTEQsuw2QupaxzG1a4PqYCOeLEk26+Im
        |588YUy/jr83hSl6Kfp04VtCxisSIkIlLvENqBptuG2iaDqvNlJm/F8zwkxZDzzMs
        |4uawa7Og+rPldJIo7gxrP/jo6TogRu0rGLF5iRrHRhGc5RyjMEXrHq5W/JFqSITl
        |FFLiX6YqZMz+PQV7AgMBAAGjUzBRMB0GA1UdDgQWBBSy9Dp8fvVNWWub8/qabCSo
        |cfBbkTAfBgNVHSMEGDAWgBSy9Dp8fvVNWWub8/qabCSocfBbkTAPBgNVHRMBAf8E
        |BTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQA2sKefy514FOUC5tXVLT+bJ4QxT2Zh
        |iMGBpMjNt+a1VvzNZb74m+B5St43EjtstGEPMrF0uyokvltnx+R15CL3qTDtYZzj
        |1Pn13qPbutXNAJX1QzfooOMUjTTADhm9YP1A9c7ERs1YQQ8p0OLZEYmNBlDaMOHX
        |lStiNZaSYwqSvza2zqM9sNBPSE4LvLrqFFLRNtrP8UlYTKo0bJOhc9ooGJgCeI+w
        |Qs7BMnTYNCawuJHCbwjJi7O/NEHJbatYOiqzC1ucu45zhid6ICyBQ+yU8RHOGTe4
        |VLIDeOdztDHQfg7zH3anm73UTM4PmqocecUrYC2okVcIdGRajzwNQolh
        |-----END CERTIFICATE-----
      """.trimMargin()
    val x509PemObjects = loadPemContent(x509Content)
    assertFalse { x509PemObjects.asAsymmetricKeyParameter().isPrivate }

    val unknownContent =
      """
        |-----BEGIN PUBLIC KEY-----
        |MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwNMGJbumHaYBtjp7cq/w
        |zJuSwqCBngk+HbWxWwatjuR6QtkhR67o1YbImEcmWZNwjADKD3aFeOxRmGmtnJZ1
        |/Xf8SeHw0T8VYyx15YpOJ1aP/T3cSiKENl+igtzeTU9d9AEzpouXQBgn2YWo7fvn
        |ATLt2FeDofWp3AUk5G8wfmZcZsx2XNzueIK8NNuk/+5ZKZp9FspPm6+Tp0Kljoxi
        |F0jV8lgmbJqJOTVQvorqXPvRlTfmVTv/SFUVLfkyEN65UeiuGwX8VJGdV17PHP2n
        |7zf4KpgJbIYZBWxSQOAooFsMh4u+6hHpHsoNVQmWwDpLtGwKDG78Vfl0NTCiLY+i
        |dwIDAQAB
        |-----END PUBLIC KEY-----
      """.trimMargin()
    val unknownPemObjects = loadPemContent(unknownContent)
    assertThrows<InvalidKeySpecException> { unknownPemObjects.asAsymmetricKeyParameter() }
  }

  @Test
  fun `PemObject or Asymmetric`() {
    val certContent =
      """
        |-----BEGIN CERTIFICATE-----
        |MIIEFjCCAv6gAwIBAgIJAKgxIwV0NU0nMA0GCSqGSIb3DQEBCwUAMIGeMQswCQYD
        |VQQGEwJjbjESMBAGA1UECAwJR3Vhbmdkb25nMRIwEAYDVQQHDAlHdWFuZ3pob3Ux
        |FzAVBgNVBAoMDkVyaWNzc29uLCBJbmMuMREwDwYDVQQLDAhlcmljc3NvbjEVMBMG
        |A1UEAwwMZXJpY3Nzb24uY29tMSQwIgYJKoZIhvcNAQkBFhVnYWx1ZGlzdUBlcmlj
        |c3Nvbi5jb20wIBcNMjEwNzEyMDI0NzM1WhgPMzAyMDExMTIwMjQ3MzVaMIGeMQsw
        |CQYDVQQGEwJjbjESMBAGA1UECAwJR3Vhbmdkb25nMRIwEAYDVQQHDAlHdWFuZ3po
        |b3UxFzAVBgNVBAoMDkVyaWNzc29uLCBJbmMuMREwDwYDVQQLDAhlcmljc3NvbjEV
        |MBMGA1UEAwwMZXJpY3Nzb24uY29tMSQwIgYJKoZIhvcNAQkBFhVnYWx1ZGlzdUBl
        |cmljc3Nvbi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDdT7et
        |D1Dhv8bfQvnjGMpEtDnl70Wv7rfrFjxRM99rKd0WrPlCtXRuzGYpEBTqdoQHRaMn
        |FAerHVHrwFBIxgaHNcgb6wv6Xk7Zebgq4loQiQU2UO+L8TWKqB5yRBzi68v90E3z
        |+8Kigi99XIldtkCcOkYs34np4uHM8jMLGTEQsuw2QupaxzG1a4PqYCOeLEk26+Im
        |588YUy/jr83hSl6Kfp04VtCxisSIkIlLvENqBptuG2iaDqvNlJm/F8zwkxZDzzMs
        |4uawa7Og+rPldJIo7gxrP/jo6TogRu0rGLF5iRrHRhGc5RyjMEXrHq5W/JFqSITl
        |FFLiX6YqZMz+PQV7AgMBAAGjUzBRMB0GA1UdDgQWBBSy9Dp8fvVNWWub8/qabCSo
        |cfBbkTAfBgNVHSMEGDAWgBSy9Dp8fvVNWWub8/qabCSocfBbkTAPBgNVHRMBAf8E
        |BTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQA2sKefy514FOUC5tXVLT+bJ4QxT2Zh
        |iMGBpMjNt+a1VvzNZb74m+B5St43EjtstGEPMrF0uyokvltnx+R15CL3qTDtYZzj
        |1Pn13qPbutXNAJX1QzfooOMUjTTADhm9YP1A9c7ERs1YQQ8p0OLZEYmNBlDaMOHX
        |lStiNZaSYwqSvza2zqM9sNBPSE4LvLrqFFLRNtrP8UlYTKo0bJOhc9ooGJgCeI+w
        |Qs7BMnTYNCawuJHCbwjJi7O/NEHJbatYOiqzC1ucu45zhid6ICyBQ+yU8RHOGTe4
        |VLIDeOdztDHQfg7zH3anm73UTM4PmqocecUrYC2okVcIdGRajzwNQolh
        |-----END CERTIFICATE-----
      """.trimMargin()
    val certPemObject = loadPemContent(certContent)
    assertThat(certPemObject.asX509(), isA(X509Certificate::class.java))
    assertTrue { certPemObject.asX509().isCa() }
  }

  @Throws(IOException::class)
  private fun loadPemContent(content: String): PemObject {
    return org.bouncycastle.util.io.pem.PemReader(StringReader(content)).use { p ->
      p.readPemObject()
    }
  }

  private fun createPrivateKey(algorithm: String): PrivateKey = createPairKey(algorithm) { a -> a.private }

  private fun createPublicKey(algorithm: String): PublicKey = createPairKey(algorithm) { a -> a.public }

  private fun <T> createPairKey(
    algorithm: String,
    func: (KeyPair) -> T,
  ): T {
    val keyPairGenerator = KeyPairGenerator.getInstance(algorithm)
    val generateKeyPair = keyPairGenerator.generateKeyPair()
    return func(generateKeyPair)
  }

  @Throws(NoSuchAlgorithmException::class)
  private fun createSubjectPublicKeyInfo(
    algorithm: String,
    signatureAlgorithm: String,
  ): SubjectPublicKeyInfo {
    val keyPairGenerator = KeyPairGenerator.getInstance(algorithm)
    val rootKeyPair = keyPairGenerator.generateKeyPair()
    val rootCertIssuer = X500Name("CN=root-cert")
    val p10Builder = JcaPKCS10CertificationRequestBuilder(rootCertIssuer, rootKeyPair.public)
    val csrBuilder = JcaContentSignerBuilder(signatureAlgorithm)
    val csrContentSigner = csrBuilder.build(rootKeyPair.private)
    val csr = p10Builder.build(csrContentSigner)
    return csr.subjectPublicKeyInfo
  }
}
