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

import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import java.security.Key

abstract class KEY<out A>(private val algorithm: String) : Key where A : AsymmetricKeyParameter {
  abstract val delegate: A

  override fun getFormat(): String? = null

  override fun getEncoded(): ByteArray? = byteArrayOf()

  override fun getAlgorithm(): String = algorithm
}
