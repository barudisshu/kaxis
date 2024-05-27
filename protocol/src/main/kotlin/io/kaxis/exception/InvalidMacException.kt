/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
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
