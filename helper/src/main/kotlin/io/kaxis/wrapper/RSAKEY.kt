/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.wrapper

import io.kaxis.RSA
import org.bouncycastle.crypto.params.RSAKeyParameters
import java.math.BigInteger

abstract class RSAKEY<T> : KEY<T>(RSA) where T : RSAKeyParameters {
  fun getModulus(): BigInteger = delegate.modulus
}
