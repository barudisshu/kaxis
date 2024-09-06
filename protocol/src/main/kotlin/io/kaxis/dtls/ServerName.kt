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

import io.kaxis.util.Utility
import java.nio.charset.StandardCharsets
import java.util.*

/**
 *  A typed server name as defined by RFC 6066, Section 3.
 */
class ServerName private constructor(val type: NameType, val name: ByteArray) {
  companion object {
    @JvmField
    val CHARSET = StandardCharsets.US_ASCII

    fun from(
      type: NameType?,
      name: ByteArray?,
    ): ServerName {
      requireNotNull(type) { "type must not be null" }
      requireNotNull(name) { "name must not be null" }
      return if (type == NameType.HOST_NAME) {
        fromHostName(String(name, CHARSET))
      } else {
        ServerName(type, name)
      }
    }

    fun fromHostName(hostName: String?): ServerName {
      requireNotNull(hostName) { "host name must not be null" }
      if (Utility.isValidHostName(hostName)) {
        return ServerName(NameType.HOST_NAME, hostName.lowercase(Locale.getDefault()).toByteArray(CHARSET))
      } else {
        throw IllegalArgumentException("not a valid host name")
      }
    }
  }

  val hashCode: Int

  val length: Int
    get() = name.size

  /**
   * Gets the name as a string using ASCII encoding.
   */
  val nameAsString
    get() = String(name, CHARSET)

  init {
    this.hashCode = 31 * name.contentHashCode() + type.hashCode()
  }

  override fun hashCode(): Int {
    return hashCode
  }

  /**
   * Checks whether this instance is the same as another object.
   * @param other the object to compare to.
   * @return `true` if the other object is a [ServerName] and has hte same type and name property values.
   */
  override fun equals(other: Any?): Boolean {
    if (this === other) {
      return true
    }
    if (other == null) {
      return false
    }
    if (other !is ServerName) {
      return false
    }
    if (type != other.type) {
      return false
    }
    return name.contentEquals(other.name)
  }

  /**
   * The enumeration of name types defined for the _Server Name Indication_ extension.
   */
  enum class NameType(val code: Int) {
    /**
     * The host name type.
     */
    HOST_NAME(0x00),

    /**
     * Undefined type.
     */
    UNDEFINED(0xFF),
    ;

    companion object {
      /**
       * Gets the name type for a code.
       * @param code the type code.
       * @return the type or `null` of no tpe with the given code is defined.
       */
      fun fromCode(code: Int): NameType {
        entries.forEach { type ->
          if (type.code == code) {
            return type
          }
        }
        return UNDEFINED
      }
    }
  }
}
