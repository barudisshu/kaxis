/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.exception

import io.kaxis.Bytes
import java.security.GeneralSecurityException

/**
 * This exception is thrown when a MAC validation fails.
 */
class InvalidMacException : GeneralSecurityException {
  companion object {
    private const val DEFAULT_MESSAGE = "MAC validation failed!"
  }

  val expected: ByteArray
  val actual: ByteArray

  /**
   * Create generic invalid MAC exception without actual MAC values.
   */
  constructor() : this(DEFAULT_MESSAGE)

  /**
   * Create invalid MAC exception without actual MAC values.
   * @param msg message
   */
  constructor(msg: String?) : super(msg) {
    this.expected = Bytes.EMPTY_BYTES
    this.actual = Bytes.EMPTY_BYTES
  }

  /**
   * Sets the expected and actual MAC values.
   * @param expected the expected MAC value
   * @param actual the actual MAC value
   */
  constructor(expected: ByteArray, actual: ByteArray) : super(DEFAULT_MESSAGE) {
    this.expected = expected.copyOf(expected.size)
    this.actual = actual.copyOf(actual.size)
  }
}
