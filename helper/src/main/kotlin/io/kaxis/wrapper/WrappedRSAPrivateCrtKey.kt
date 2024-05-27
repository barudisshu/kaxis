/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.wrapper

import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import java.math.BigInteger
import java.security.interfaces.RSAPrivateCrtKey

class WrappedRSAPrivateCrtKey<T : RSAPrivateCrtKeyParameters>(override val delegate: T) :
  RSAKEY<T>(),
  RSAPrivateCrtKey {
  override fun getPrivateExponent(): BigInteger = delegate.exponent

  override fun getPublicExponent(): BigInteger = delegate.publicExponent

  override fun getPrimeP(): BigInteger = delegate.p

  override fun getPrimeQ(): BigInteger = delegate.q

  override fun getPrimeExponentP(): BigInteger = delegate.dp

  override fun getPrimeExponentQ(): BigInteger = delegate.dq

  override fun getCrtCoefficient(): BigInteger = delegate.qInv
}
