/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls

/**
 * Represents the possible types of a handshake message. See [RFC 5246](https://tools.ietf.org/html/rfc5246#section-7.4) for details.
 */
enum class HandshakeType(val code: Int) {
  HELLO_REQUEST(0),
  CLIENT_HELLO(1),
  SERVER_HELLO(2),
  HELLO_VERIFY_REQUEST(3),
  CERTIFICATE(11),
  SERVER_KEY_EXCHANGE(12),
  CERTIFICATE_REQUEST(13),
  SERVER_HELLO_DONE(14),
  CERTIFICATE_VERIFY(15),
  CLIENT_KEY_EXCHANGE(16),
  FINISHED(20),
  ;

  override fun toString(): String {
    return "$name ($code)"
  }

  companion object {
    @JvmStatic
    fun getTypeByCode(code: Int): HandshakeType? {
      entries.forEach {
        if (it.code == code) {
          return it
        }
      }
      return null
    }
  }
}
