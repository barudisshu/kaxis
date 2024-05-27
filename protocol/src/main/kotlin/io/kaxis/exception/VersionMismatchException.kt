/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.exception

class VersionMismatchException : IllegalArgumentException {
  val readVersion: Int

  constructor(readVersion: Int) : super() {
    this.readVersion = readVersion
  }

  constructor(message: String, readVersion: Int) : super(message) {
    this.readVersion = readVersion
  }
}
