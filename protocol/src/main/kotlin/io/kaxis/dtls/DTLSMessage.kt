/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls

/**
 * The message contract as defined by the DTLS specification.
 * @author galudisu
 */
interface DTLSMessage {
  /**
   * Gets the number of bytes representing this message as defined by [TLS 1.2, Appendix A](https://tools.ietf.org/html/rfc5246#appendix-A)
   * @return number of bytes
   */
  val size: Int

  /**
   * Gets the byte array representation of this message as defined by [TLS 1.2, Appendix A](https://tools.ietf.org/html/rfc5246#appendix-A)
   * @return the byte array
   */
  fun toByteArray(): ByteArray?

  /**
   * Gets the message's content type.
   * @return the type
   */
  val contentType: ContentType

  /**
   * Gets the textual presentation of this message.
   * @param indent line indentation
   * @return textual presentation
   */
  fun toString(indent: Int): String
}
