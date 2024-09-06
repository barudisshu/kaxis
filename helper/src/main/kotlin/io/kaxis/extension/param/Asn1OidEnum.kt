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

/**
 * Supported ASN.1 Object Identifier.
 * @author galudisu
 *
 */
enum class Asn1OidEnum(val asn1Oid: ASN1ObjectIdentifier) {
  DES_EDE3_CBC(PKCSObjectIdentifiers.des_EDE3_CBC),
  AES_128_CBC(NISTObjectIdentifiers.id_aes128_CBC),
  AES_192_CBC(NISTObjectIdentifiers.id_aes192_CBC),
  AES_256_CBC(NISTObjectIdentifiers.id_aes256_CBC),
  PBE_WITH_SHA_AND_128_BIT_RC4(PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC4),
  PBE_WITH_SHA_AND_40BIT_RC4(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC4),
  PBE_WITH_SHA_AND_2_KEY_TRIPLEDES_CBC(PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC),
  PBE_WITH_SHA_AND_3_KEY_TRIPLEDES_CBC(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC),
  PBE_WITH_SHA_AND_128BIT_RC2_CBC(PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC),
  PBE_WITH_SHA_AND_40BIT_RC2_CBC(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC),
  ;

  companion object {
    fun from(asn1Oid: String?): Asn1OidEnum = entries.find { it.asn1Oid.id == asn1Oid } ?: AES_128_CBC
  }
}
