/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.extension

import io.kaxis.BCProvider
import io.kaxis.extension.generator.KaxisBcFabric
import io.kaxis.extension.param.AlgEnum
import org.bouncycastle.asn1.x500.X500Name
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.KeyPair
import java.security.KeyPairGenerator

/**
 * Almost the same with [org.bouncycastle.jcajce.util.DefaultJcaJceHelper]
 *
 * @author galudisu
 */
class DefaultKaxisBcJcaGenerator : AbstractKaxisBcJcaGenerator() {
  companion object {
    private val LOGGER: Logger = LoggerFactory.getLogger(DefaultKaxisBcJcaGenerator::class.java)
  }

  /**
   * Also NOTE that there are good quality domain parameters available for both DSA and Diffie-Hellman and thus there is no need to genrate your own. A common performance issued with DSA and Diffie-Hellman keys are due to users generating their own parameters when there is no need to; parameter generation for both these algorithms is quite expensive.
   */
  override fun spawn(algParameter: AlgParameter): JcaMiscPemGroove {
    fun getInstance(
      algorithm: String,
      provider: String,
    ): KeyPair {
      val keyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider)
      if (algParameter.type == AlgEnum.DSA) {
        keyPairGenerator.initialize(generateDsaParameters(algParameter))
      } else {
        keyPairGenerator.initialize(algParameter.keySize)
      }
      return keyPairGenerator.generateKeyPair()
    }

    val timeSlot = KaxisBcFabric.generateTimeSlot(algParameter.aliveYears)

    // ROOT
    val rootKeyPair = getInstance(algParameter.type.name, BCProvider.PROVIDER_NAME)
    val rootCertIssuer = X500Name(algParameter.caIssuer)
    val rootJcaKeyPair =
      KaxisBcFabric.generateX509CaChain(rootKeyPair, timeSlot, rootCertIssuer, algParameter.sigAlgName)
    LOGGER.info("Spawning ASN.1 {}", algParameter.sigAlgOid.id)

    val rootCert = rootJcaKeyPair.x509Certificate

    val generateFunc: (String, String, String, String, String, KeyPair) -> KaxisBcFabric.JcaKeyPair =
      { algorithm, provider, issuer, dnsName, ipAddress, keyPair ->
        val certKeyPair = getInstance(algorithm, provider)
        val certSubject = X500Name(issuer)

        KaxisBcFabric.generateX509CertificateAndKey(
          keyPair,
          certKeyPair,
          rootCert,
          rootCertIssuer,
          certSubject,
          timeSlot,
          dnsName,
          ipAddress,
          algParameter.sigAlgName,
        )
      }

    // SERVER
    val serverJcaKeyPair =
      generateFunc(
        algParameter.type.name,
        BCProvider.PROVIDER_NAME,
        algParameter.serverIssuer,
        algParameter.serverDnsName,
        algParameter.serverIpAddress,
        rootKeyPair,
      )

    // CLIENT
    val clientJcaKeyPair =
      generateFunc(
        algParameter.type.name,
        BCProvider.PROVIDER_NAME,
        algParameter.clientIssuer,
        algParameter.clientDnsName,
        algParameter.clientIpAddress,
        rootKeyPair,
      )

    return JcaMiscPemGroove(rootJcaKeyPair, serverJcaKeyPair, clientJcaKeyPair)
  }
}
