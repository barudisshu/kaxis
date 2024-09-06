/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.message

import io.kaxis.dtls.ContentType
import io.kaxis.dtls.DTLSMessage
import io.kaxis.util.Utility

/**
 * Application data messages are carried by the record layer and are fragmented, compressed, and encrypted based
 * on the current connection state.
 *
 * The messages are treated as transparent data to the record layer.
 */
class ApplicationMessage
/**
   * Create a new _APPLICATION_DATA_ message containing specific data.
   *
   * The given byte array will not be cloned/copied, i.e. any change made to the byte array after this method
   * has been invoked will be exposed in the message's payload.
   * @param data byte array with the application data.
   * @throws NullPointerException if peer or data is `null`.
   */
  constructor(data: ByteArray?) : DTLSMessage {
    companion object {
      @JvmStatic
      fun fromByteArray(byteArray: ByteArray?): DTLSMessage = ApplicationMessage(byteArray)
    }

    /**
     * The (to the record layer) transparent data.
     */
    val data: ByteArray

    init {
      requireNotNull(data) { "data must not be null!" }
      this.data = data
    }

    override val size: Int
      get() = data.size

    override fun toByteArray(): ByteArray = data

    override val contentType: ContentType = ContentType.APPLICATION_DATA

    override fun toString(indent: Int): String {
      return StringBuilder().apply sb@{
        val indentation = Utility.indentation(indent)
        if (indent > 0) {
          this@sb.append(indentation)
        }
        this@sb.append("Application Data: ")
          .append(Utility.byteArray2HexString(data, Utility.NO_SEPARATOR, 32))
        if (indent > 0) {
          this@sb.append(Utility.LINE_SEPARATOR)
        }
      }.toString()
    }

    override fun toString(): String {
      return toString(0)
    }
  }
