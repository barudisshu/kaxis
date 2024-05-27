/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.wrapper

import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import java.math.BigInteger
import java.security.interfaces.ECPrivateKey

class WrappedECPrivateKey<T : ECPrivateKeyParameters>(override val delegate: T) : ECKEY<T>(), ECPrivateKey {
  override fun getS(): BigInteger = delegate.d
}
