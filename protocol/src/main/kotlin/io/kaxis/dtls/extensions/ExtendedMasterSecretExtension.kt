/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.extensions

import io.kaxis.dtls.ExtendedMasterSecretMode
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter

/**
 * Extended master secret extension.
 * See [RFC 7627](https://tools.ietf.org/html/rfc7627) and [ExtendedMasterSecretMode] for additional details.
 */
class ExtendedMasterSecretExtension : HelloExtension(ExtensionType.EXTENDED_MASTER_SECRET) {
  companion object {
    val INSTANCE = ExtendedMasterSecretExtension()

    /**
     * Create extended master secret extension from extensions data bytes.
     * @param extensionDataReader extension data bytes
     * @return crated extended master secret extension
     * @throws NullPointerException if extensionData is `null`.
     */
    fun fromExtensionDataReader(extensionDataReader: DatagramReader?): ExtendedMasterSecretExtension {
      requireNotNull(extensionDataReader) { "extended master secret must not be null!" }
      return INSTANCE
    }
  }

  override val extensionLength: Int
    get() = 0

  override fun writeExtensionTo(writer: DatagramWriter) {
    // empty
  }
}