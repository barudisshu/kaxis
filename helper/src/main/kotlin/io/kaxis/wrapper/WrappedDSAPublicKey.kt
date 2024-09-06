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

import org.bouncycastle.crypto.params.DSAPublicKeyParameters
import java.math.BigInteger
import java.security.interfaces.DSAPublicKey

class WrappedDSAPublicKey<T : DSAPublicKeyParameters>(override val delegate: T) : DSAKEY<T>(), DSAPublicKey {
  override fun getY(): BigInteger = delegate.y
}
