/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.wrapper

import org.bouncycastle.crypto.params.ECPublicKeyParameters
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPoint

class WrappedECPublicKey<T : ECPublicKeyParameters>(override val delegate: T) : ECKEY<T>(), ECPublicKey {
  override fun getW(): ECPoint = ECPoint(delegate.q.xCoord.toBigInteger(), delegate.q.yCoord.toBigInteger())
}
