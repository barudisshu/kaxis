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

import io.kaxis.RSA
import org.bouncycastle.crypto.params.RSAKeyParameters
import java.math.BigInteger

abstract class RSAKEY<T> : KEY<T>(RSA) where T : RSAKeyParameters {
  fun getModulus(): BigInteger = delegate.modulus
}
