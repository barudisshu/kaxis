/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.wrapper

import org.bouncycastle.crypto.params.DSAPublicKeyParameters
import java.math.BigInteger
import java.security.interfaces.DSAPublicKey

class WrappedDSAPublicKey<T : DSAPublicKeyParameters>(override val delegate: T) : DSAKEY<T>(), DSAPublicKey {
  override fun getY(): BigInteger = delegate.y
}
