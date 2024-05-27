/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls

import io.kaxis.Bytes

/**
 * Implementation of byte array based PSK public information (hint or identity).
 *
 * Note: [RFC 4279, Section 5.1](https://tools.ietf.org/html/rfc4279#section-5.1)
 * defines to use UTF-8 to encode the identities. However, some pers seems to use non UTF-8 encoded identities.
 * This byte array based implementation allows to support such non-compliant clients. The string based identity is used
 * for [PreSharedKeyIdentity], therefore it's required to use [PskPublicInformation] to setup a proper name for such
 * non-compliant peers in the [AdvancedPskStore]. During the lookup of the secret key in the handshake, such a non-compliant
 * identity is normalized with the identity provided by the store.
 */
class PskPublicInformation : Bytes {
  companion object {
    val EMPTY = PskPublicInformation("")

    private const val MAX_LENGTH = 65535

    /**
     * Create public information from received byte array.
     * @param byteArray received byte array
     * @return public information
     * @throws IllegalArgumentException if public information length is larger than [MAX_LENGTH].
     */
    fun fromByteArray(byteArray: ByteArray?): PskPublicInformation {
      if (byteArray == null || byteArray.isEmpty()) {
        return EMPTY
      }
      return PskPublicInformation(byteArray)
    }
  }

  /**
   * `true`, if the byte array contains the string compliant encoded in UTF-8.
   */
  var compliantEncoding: Boolean

  /**
   * Public information as string. The "hint" or "identity".
   */
  private var publicInfo: String

  /**
   * Get public information as string.
   */
  val publicInfoAsString: String
    get() = publicInfo

  /**
   * Create PSK public information from bytes (identity or hint). Used by [fromByteArray] for received public information (identity or hint).
   * @param publicInfoBytes PSK public information encoded as bytes. Identity or hint.
   * @throws NullPointerException if public information is `null`
   * @throws IllegalArgumentException if public information length is larger than [MAX_LENGTH].
   */
  private constructor(publicInfoBytes: ByteArray) : this(String(publicInfoBytes), publicInfoBytes)

  /**
   * Create PSK public information from string (identity or hint).
   * @param publicInfo PSK public information as string. Identity or hint.
   * @throws NullPointerException if public information is `null`
   * @throws IllegalArgumentException if public information length is larger than [MAX_LENGTH].
   */
  constructor(publicInfo: String?) : super(
    publicInfo?.toByteArray(),
    MAX_LENGTH,
    false,
  ) {
    requireNotNull(publicInfo) { "Public information can not be null!" }
    this.publicInfo = publicInfo
    this.compliantEncoding = true
  }

  /**
   * Create PSK public information from string and bytes (identity or hint). Enables to create public
   * information for none-compliant encodings!
   *
   * Note: Please use this with care! Prefer to fix the clients and use it only as temporary workaround!
   * @param publicInfo PSK public information as string. Identity or hint.
   * @param publicInfoBytes PSK public information encoded as bytes. Identity or hint.
   * @throws NullPointerException if one of the parameters are `null`
   * @throws IllegalArgumentException if public information encoded as bytes is larger than [MAX_LENGTH].
   */
  constructor(publicInfo: String?, publicInfoBytes: ByteArray) : super(publicInfoBytes, MAX_LENGTH, false) {
    requireNotNull(publicInfo) { "Public information can not be null!" }
    this.publicInfo = publicInfo
    this.compliantEncoding = publicInfoBytes.contentEquals(publicInfo.toByteArray())
  }

  /**
   * Normalize public information. Overwrite the decoded string with the intended string. Intended to be used
   * during the PSK lookup and called, if a bytes-matching entry was found. The normalized string could then
   * be used to create a [PreSharedKeyIndentity].
   * @param publicInfo PSK public information as string. Identity or hint.
   * @throws NullPointerException if public information is `null`
   * @throws IllegalArgumentException if public information is empty.
   */
  fun normalize(publicInfo: String?) {
    requireNotNull(publicInfo) { "public information must not be null" }
    require(publicInfo.isNotEmpty()) { "public information must not be empty" }
    this.publicInfo = publicInfo
    this.compliantEncoding = byteArray.contentEquals(publicInfo.toByteArray())
  }

  override fun toString(): String {
    return if (compliantEncoding) {
      publicInfo
    } else {
      "$publicInfo/$asString"
    }
  }
}
