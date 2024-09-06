/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.util

import io.kaxis.Bytes
import java.security.spec.AlgorithmParameterSpec
import java.util.*
import javax.security.auth.Destroyable

/**
 * Secure initial vector parameter specification. Additional [Destroyable] to clear the iv after usage.
 */
class SecretIvParameterSpec : AlgorithmParameterSpec, Destroyable {
  /**
   * The implicit iv.
   */
  val iv: ByteArray

  /**
   * Get size of iv.
   */
  val size: Int
    get() = iv.size

  /**
   * Indicates, that this instance has been [destroy]ed.
   */
  var destroyed: Boolean = false

  /**
   * Create new secure iv parameters.
   * @param iv byte array
   * @throws NullPointerException if iv is `null`
   * @throws IllegalArgumentException if iv is empty
   */
  constructor(iv: ByteArray?) : this(iv, 0, iv?.size ?: 0)

  /**
   * Create new secure iv parameters.
   * @param iv byte array
   * @throws NullPointerException if iv is `null`
   */
  constructor(iv: SecretIvParameterSpec?) {
    requireNotNull(iv) { "IV missing" }
    this.iv = iv.iv.copyOf(iv.iv.size)
  }

  /**
   * Create new iv parameters.
   * @param iv byte array with the iv.
   * @param offset offset of the iv within the byte array
   * @param length length of the iv within th byte array
   * @throws NullPointerException if iv is `null`
   * @throws IllegalArgumentException if iv is empty, or length is negative or offset and length doesn't fit into iv.
   */
  constructor(iv: ByteArray?, offset: Int, length: Int) {
    requireNotNull(iv) { "IV missing" }
    require(iv.isNotEmpty()) { "IV is empty" }
    if (length < 0) {
      throw ArrayIndexOutOfBoundsException("len is negative")
    }
    require(iv.size - offset >= length) { "Invalid offset/length combination" }
    this.iv = Arrays.copyOfRange(iv, offset, offset + length)
  }

  /**
   * Write iv to writer.
   * @param writer to write iv to
   */
  fun writeTo(writer: DatagramWriter) {
    writer.writeBytes(iv)
  }

  override fun destroy() {
    Bytes.clear(iv)
    destroyed = true
  }

  override fun isDestroyed(): Boolean {
    return destroyed
  }
}
