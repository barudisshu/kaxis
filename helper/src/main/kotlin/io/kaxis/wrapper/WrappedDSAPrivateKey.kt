/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.wrapper

import org.bouncycastle.crypto.params.DSAPrivateKeyParameters
import java.math.BigInteger
import java.security.interfaces.DSAPrivateKey

class WrappedDSAPrivateKey<T : DSAPrivateKeyParameters>(override val delegate: T) : DSAKEY<T>(), DSAPrivateKey {
  override fun getX(): BigInteger = delegate.x
}
