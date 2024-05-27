/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.wrapper

import io.kaxis.DSA
import org.bouncycastle.crypto.params.DSAKeyParameters
import java.math.BigInteger
import java.security.interfaces.DSAParams

abstract class DSAKEY<T> : KEY<T>(DSA) where T : DSAKeyParameters {
  fun getParams(): DSAParams =
    object : DSAParams {
      override fun getP(): BigInteger = delegate.parameters.p

      override fun getQ(): BigInteger = delegate.parameters.q

      override fun getG(): BigInteger = delegate.parameters.g
    }
}
