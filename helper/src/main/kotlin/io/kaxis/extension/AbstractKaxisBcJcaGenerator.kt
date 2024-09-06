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

import org.bouncycastle.crypto.CryptoServicesRegistrar
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.DSAParametersGenerator
import org.bouncycastle.crypto.params.DSAParameterGenerationParameters
import org.bouncycastle.crypto.params.DSAParameters
import org.bouncycastle.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator
import org.bouncycastle.jcajce.util.BCJcaJceHelper
import org.bouncycastle.jcajce.util.JcaJceHelper
import java.security.spec.DSAParameterSpec
import java.security.spec.InvalidParameterSpecException

/**
 * The bouncycastle JCA generator.
 * @author galudisu
 */
abstract class AbstractKaxisBcJcaGenerator : KaxisBcJcaGenerator {
  protected val helper: JcaJceHelper = BCJcaJceHelper()

  /**
   * Also see [org.bouncycastle.jcajce.provider.asymmetric.dsa.AlgorithmParameterGeneratorSpi.engineInit].
   * @param algParameter DSA algorithm parameter generator spi
   * @return [DSAParameterSpec]
   */
  protected fun generateDsaParameters(algParameter: AlgParameter): DSAParameterSpec {
    val strength = algParameter.keySize
    if (strength < 512 || strength > 3072) {
      throw InvalidParameterSpecException("strength must be from 512 - 3072.")
    }
    if (strength <= 1024 && strength % 64 != 0) {
      throw InvalidParameterSpecException("strength must be a multiple of 64 below 1024 bits.")
    }
    if (strength > 1024 && strength % 1024 != 0) {
      throw InvalidParameterSpecException("strength must be a multiple of 1024 above 1024 bits.")
    }
    val dsaParameters = generateDsaParameters(strength)
    return DSAParameterSpec(dsaParameters.p, dsaParameters.q, dsaParameters.g)
  }

  private fun generateDsaParameters(strength: Int): DSAParameters {
    val random = CryptoServicesRegistrar.getSecureRandom()

    val parameterGen: DSAParametersGenerator =
      if (strength <= 1024) {
        DSAParametersGenerator()
      } else {
        DSAParametersGenerator(SHA256Digest())
      }
    val certainty = PrimeCertaintyCalculator.getDefaultCertainty(strength)

    val params: DSAParameterGenerationParameters
    if (strength == 1024) {
      params = DSAParameterGenerationParameters(1024, 160, certainty, random)
      parameterGen.init(params)
    } else if (strength > 1024) {
      params = DSAParameterGenerationParameters(strength, 256, certainty, random)
      parameterGen.init(params)
    } else {
      parameterGen.init(strength, certainty, random)
    }
    return parameterGen.generateParameters()
  }
}
