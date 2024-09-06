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
