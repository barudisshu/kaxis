/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.extensions

import io.kaxis.dtls.CertificateType
import io.kaxis.util.DatagramReader

class ServerCertificateTypeExtension : CertificateTypeExtension {
  companion object {
    /**
     * Constructs a server certificate type extension with a list of supported certificate types, or a selected
     * certificate type chosen by the server.
     * @param extensionDataReader the list of supported certificate types or the selected certificate
     * type encoded in bytes.
     * @return the created certificate type extension
     * @throws NullPointerException if extension data is `null`
     * @throws IllegalArgumentException if extension data is empty
     */
    fun fromExtensionDataReader(extensionDataReader: DatagramReader?): ServerCertificateTypeExtension {
      return ServerCertificateTypeExtension(extensionDataReader)
    }
  }

  private constructor(extensionDataReader: DatagramReader?) : super(
    ExtensionType.SERVER_CERT_TYPE,
    extensionDataReader,
  )

  /**
   * Constructs a server-side certificate type extension with a list of supported certificate types.
   * @param certificateTypes the list of supported certificate types.
   */
  constructor(certificateTypes: List<CertificateType>?) : super(ExtensionType.SERVER_CERT_TYPE, certificateTypes)

  /**
   * Constructs a server-side certificate type extension with the supported certificate type.
   * @param certificateType the supported certificate type.
   */
  constructor(certificateType: CertificateType?) : super(ExtensionType.SERVER_CERT_TYPE, certificateType)

  override fun toString(indent: Int): String {
    return super.toString(indent, "Server")
  }
}
