/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.wrapper

import io.kaxis.ECDSA
import org.bouncycastle.crypto.params.ECKeyParameters
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint

abstract class ECKEY<T> : KEY<T>(ECDSA) where T : ECKeyParameters {
  fun getParams(): ECParameterSpec =
    ECParameterSpec(
      EC5Util.convertCurve(delegate.parameters.curve, delegate.parameters.seed),
      ECPoint(delegate.parameters.g.xCoord.toBigInteger(), delegate.parameters.g.yCoord.toBigInteger()),
      delegate.parameters.n,
      delegate.parameters.h.intValueExact(),
    )
}
