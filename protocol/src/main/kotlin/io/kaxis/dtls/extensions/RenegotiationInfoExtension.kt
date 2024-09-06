/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.extensions

import io.kaxis.dtls.message.AlertMessage
import io.kaxis.exception.HandshakeException
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter

/**
 * Renegotiation info extension.
 * /!\ NOT IN USED /!\
 */
class RenegotiationInfoExtension : HelloExtension(ExtensionType.RENEGOTIATION_INFO) {
  companion object {
    val INSTANCE = RenegotiationInfoExtension()

    /**
     * create renegotiation info extension from extensions data bytes.
     * @param extensionDataReader extension data bytes
     * @return created renegotiation info extension
     * @throws NullPointerException if extensionData is `null`
     * @throws HandshakeException if renegotiation info is not empty
     */
    fun fromExtensionDataReader(extensionDataReader: DatagramReader?): RenegotiationInfoExtension {
      requireNotNull(extensionDataReader) { "renegotiation info must not be null!" }
      if (extensionDataReader.readNextByte().toInt() != 0) {
        throw HandshakeException(
          AlertMessage(
            AlertMessage.AlertLevel.FATAL,
            AlertMessage.AlertDescription.ILLEGAL_PARAMETER,
          ),
          "renegotiation info must be empty!",
        )
      }
      return INSTANCE
    }
  }

  override val extensionLength: Int
    get() = 1

  override fun writeExtensionTo(writer: DatagramWriter) {
    // renegotiation info length 0
    writer.writeByte(0)
  }
}
