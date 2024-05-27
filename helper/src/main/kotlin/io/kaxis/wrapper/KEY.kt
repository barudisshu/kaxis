/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
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
