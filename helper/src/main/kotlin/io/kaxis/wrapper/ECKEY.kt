/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
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
