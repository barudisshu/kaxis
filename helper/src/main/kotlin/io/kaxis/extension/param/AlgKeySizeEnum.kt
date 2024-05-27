/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.extension.param

/**
 * Supported algorithm key size.
 * @author galudisu
 */
enum class AlgKeySizeEnum(val keySize: Int) {
  RSA_1024(1024),
  RSA_2048(2048),
  RSA_3072(3072),
  RSA_4096(4096),
  DSA_1024(1024),
  DSA_2048(2048),
  DSA_3072(3072),
  EC_224(224),
  EC_384(384),
  EC_256(256),
  ;

  companion object {
    fun from(keySize: Int?): AlgKeySizeEnum = entries.find { it.keySize == keySize } ?: EC_224
  }
}
