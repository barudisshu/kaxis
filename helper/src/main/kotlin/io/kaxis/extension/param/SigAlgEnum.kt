/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.extension.param

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers

/**
 * Contact with [me](mailto:galudisu@gmail.com) if there's not your Signature
 * Algorithm.
 *
 * @author galudisu
 */
enum class SigAlgEnum(
  val signatureAlgorithm: String,
  val algorithmIdentifier: ASN1ObjectIdentifier,
) {
  MD2_WITH_RSA_ENCRYPTION("MD2WITHRSAENCRYPTION", PKCSObjectIdentifiers.md2WithRSAEncryption),
  MD2_WITH_RSA("MD2WITHRSA", PKCSObjectIdentifiers.md2WithRSAEncryption),
  MD5_WITH_RSA_ENCRYPTION("MD5WITHRSAENCRYPTION", PKCSObjectIdentifiers.md5WithRSAEncryption),
  MD5_WITH_RSA("MD5WITHRSA", PKCSObjectIdentifiers.md5WithRSAEncryption),
  SHA_1_WITH_RSA_ENCRYPTION("SHA1WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha1WithRSAEncryption),
  SHA_1_WITH_RSA("SHA1WITHRSA", PKCSObjectIdentifiers.sha1WithRSAEncryption),
  SHA_224_WITH_RSA_ENCRYPTION("SHA224WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha224WithRSAEncryption),
  SHA_224_WITH_RSA("SHA224WITHRSA", PKCSObjectIdentifiers.sha224WithRSAEncryption),
  SHA_256_WITH_RSA_ENCRYPTION("SHA256WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha256WithRSAEncryption),
  SHA_256_WITH_RSA("SHA256WITHRSA", PKCSObjectIdentifiers.sha256WithRSAEncryption),
  SHA_384_WITH_RSA_ENCRYPTION("SHA384WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha384WithRSAEncryption),
  SHA_384_WITH_RSA("SHA384WITHRSA", PKCSObjectIdentifiers.sha384WithRSAEncryption),
  SHA_512_WITH_RSA_ENCRYPTION("SHA512WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha512WithRSAEncryption),
  SHA_512_WITH_RSA("SHA512WITHRSA", PKCSObjectIdentifiers.sha512WithRSAEncryption),
  SHA_1_WITH_RSA_AND_MGF1("SHA1WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS),
  SHA_256_WITH_RSA_AND_MGF1("SHA256WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS),
  SHA_384_WITH_RSA_AND_MGF1("SHA384WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS),
  SHA_512_WITH_RSA_AND_MGF1("SHA512WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS),
  RIPE_MD_160_WITH_RSA_ENCRYPTION("RIPEMD160WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160),
  RIPE_MD_160_WITH_RSA("RIPEMD160WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160),
  RIPE_MD_128_WITH_RSA_ENCRYPTION("RIPEMD128WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128),
  RIPE_MD_128_WITH_RSA("RIPEMD128WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128),
  RIPE_MD_256_WITH_RSA_ENCRYPTION("RIPEMD256WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256),
  RIPE_MD_256_WITH_RSA("RIPEMD256WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256),
  SHA_1_WITH_DSA("SHA1WITHDSA", X9ObjectIdentifiers.id_dsa_with_sha1),
  DSA_WITH_SHA1("DSAWITHSHA1", X9ObjectIdentifiers.id_dsa_with_sha1),
  SHA_224_WITH_DSA("SHA224WITHDSA", NISTObjectIdentifiers.dsa_with_sha224),
  SHA_256_WITH_DSA("SHA256WITHDSA", NISTObjectIdentifiers.dsa_with_sha256),
  SHA_384_WITH_DSA("SHA384WITHDSA", NISTObjectIdentifiers.dsa_with_sha384),
  SHA_512_WITH_DSA("SHA512WITHDSA", NISTObjectIdentifiers.dsa_with_sha512),
  SHA_1_WITH_ECDSA("SHA1WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA1),
  ECDSA_WITH_SHA1("ECDSAWITHSHA1", X9ObjectIdentifiers.ecdsa_with_SHA1),
  SHA_224_WITH_ECDSA("SHA224WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA224),
  SHA_256_WITH_ECDSA("SHA256WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA256),
  SHA_384_WITH_ECDSA("SHA384WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA384),
  SHA_512_WITH_ECDSA("SHA512WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA512),
  ;

  companion object {
    fun from(sigAlg: String?): SigAlgEnum =
      entries.find { it.signatureAlgorithm.equals(sigAlg, true) } ?: SHA_224_WITH_ECDSA
  }
}
