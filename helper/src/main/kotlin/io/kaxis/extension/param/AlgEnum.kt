/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.extension.param

/**
 * Supported Algorithm.
 * @author galudisu
 */
enum class AlgEnum {
  RSA,
  DSA,
  EC,
  ;

  companion object {
    fun from(alg: String?): AlgEnum = entries.find { it.name == alg } ?: EC
  }
}
