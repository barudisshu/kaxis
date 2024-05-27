/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.wrapper

import org.bouncycastle.crypto.params.RSAKeyParameters
import java.math.BigInteger
import java.security.interfaces.RSAPublicKey

class WrappedRSAPublicKey<T : RSAKeyParameters>(override val delegate: T) : RSAKEY<T>(), RSAPublicKey {
  override fun getPublicExponent(): BigInteger = delegate.exponent
}
