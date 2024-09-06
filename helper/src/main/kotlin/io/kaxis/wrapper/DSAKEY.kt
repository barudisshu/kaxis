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
