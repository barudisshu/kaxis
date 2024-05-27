/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls

import io.kaxis.util.DatagramReader

/**
 * The content type represents a higher-level protocol to process the enclosed fragment. It is one of the four types:
 *
 * - ChangeCipherSpec
 * - Alert
 * - Handshake
 * - ApplicationData
 *
 * For further details see [RFC 5246](https://tools.ietf.org/html/rfc5246#appendix-A.1)
 */
enum class ContentType(val code: Int) {
  CHANGE_CIPHER_SPEC(20),
  ALERT(21),
  HANDSHAKE(22),
  APPLICATION_DATA(23),
  HEARTBEAT(24), // heartbeat is not recommended.
  TLS12_CID(25),
  ;

  override fun toString(): String {
    return when (code) {
      20 -> "Change Cipher Spec (20)"
      21 -> "Alert (21)"
      22 -> "Handshake (22)"
      23 -> "Application Data (23)"
      24 -> "Heartbeat (24)"
      25 -> "TLS CID (25)"
      else -> "Unknown Content Type"
    }
  }

  companion object {
    /**
     * Returns the content type according to the given code. Needed when reconstructing a received byte array.
     * @param code the code representation of the content type (i.e., 20, 21, 22, 23, 24, 25)
     * @return the corresponding content type.
     */
    @JvmStatic
    fun getTypeByValue(code: Int): ContentType? {
      return when (code) {
        20 -> CHANGE_CIPHER_SPEC
        21 -> ALERT
        22 -> HANDSHAKE
        23 -> APPLICATION_DATA
        24 -> HEARTBEAT
        // See [Draft dtls-connection-id](https://datatracker.ietf.org/doc/draft-ietf-tls-dtls-connection-id/)
        // See [IANA code point assignment](https://mailarchive.ietf.org/arch/msg/tls/3wCyihI6Y7ZlciwcSDaQ322myYY)
        25 -> TLS12_CID
        else -> null
      }
    }

    /**
     * Returns the content type according to the message byte array.
     */
    @JvmStatic
    fun fromEncoded(encoded: ByteArray): ContentType? {
      val reader = DatagramReader(encoded)
      val type = reader.read(Record.CONTENT_TYPE_BITS)
      return getTypeByValue(type)
    }
  }
}
