/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.extension

import io.kaxis.extension.param.AlgEnum
import io.kaxis.extension.param.AlgKeySizeEnum
import io.kaxis.extension.param.Asn1OidEnum
import io.kaxis.extension.param.SigAlgEnum
import org.bouncycastle.asn1.ASN1ObjectIdentifier

/**
 * Algorithm parameter.
 * @author galudisu
 */
data class AlgParameter(
  val type: AlgEnum = AlgEnum.RSA,
  private val algKeySize: AlgKeySizeEnum = AlgKeySizeEnum.RSA_2048,
  private val sigAlg: SigAlgEnum = SigAlgEnum.SHA_256_WITH_RSA,
  val asn1Oid: Asn1OidEnum = Asn1OidEnum.AES_256_CBC,
  val encryptedPass: String? = null,
  val aliveYears: Long = 1,
  val caIssuer: String = "CN=Ca",
  val serverIssuer: String = "CN=Server",
  val serverDnsName: String = "io.kaxis.aiot",
  val serverIpAddress: String = "127.100.20.1",
  val clientIssuer: String = "CN=Client",
  val clientDnsName: String = "io.kaxis.aiot",
  val clientIpAddress: String = "127.100.20.2",
  val caCrtFile: String = "ca.crt",
  val caKeyFile: String = "ca.key",
  val caPkcs8File: String = "caPkcs8.key",
  val caPkcs12File: String = "ca.p12",
  val serverCrtFile: String = "server.crt",
  val serverKeyFile: String = "server.key",
  val serverPkcs8File: String = "serverPkcs8.key",
  val serverPkcs12File: String = "server.p12",
  val clientCrtFile: String = "client.crt",
  val clientKeyFile: String = "client.key",
  val clientPkcs8File: String = "clientPkcs8.key",
  val clientPkcs12File: String = "client.p12",
) {
  val sigAlgName: String
    get() = sigAlg.signatureAlgorithm

  val sigAlgOid: ASN1ObjectIdentifier
    get() = sigAlg.algorithmIdentifier

  val keySize: Int
    get() = algKeySize.keySize
}
