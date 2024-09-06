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

import java.io.Serializable

/**
 * Represents the DTLS protocol version.
 *
 * **Note** that the major and minor version numbers are represented as the 1's complement of the corresponding DTLS version numbers, e.g. DTLS version 1.2 is represented as bytes {254, 253}.
 *
 * See [Datagram Transport Layer Security Version 1.2 (RFC 6347), Section 4.1](https://tools.ietf.org/html/rfc6347#section-4.1) for details.
 */
class ProtocolVersion(val major: Int, val minor: Int) : Comparable<ProtocolVersion>, Serializable {
  companion object {
    /** Major version for DTLS 1.x. */
    val MAJOR_1 = 254

    /** Minor version for DTLS x.2. */
    val MINOR_2 = 253

    /** Minor version for DTLS x.0. */
    val MINOR_0 = 255

    /** Protocol version DTLS 1.2. */
    @JvmField
    val VERSION_DTLS_1_2 = ProtocolVersion(MAJOR_1, MINOR_2)

    /** Protocol version DTLS 1.0. */
    @JvmField
    val VERSION_DTLS_1_0 = ProtocolVersion(MAJOR_1, MINOR_0)

    /**
     * Get protocol version value of the provided versions.
     * @param major major version
     * @param minor minor version
     * @return protocol version
     */
    fun valueOf(
      major: Int,
      minor: Int,
    ): ProtocolVersion {
      return if (major == MAJOR_1 && minor == MINOR_2) {
        VERSION_DTLS_1_2
      } else if (major == MAJOR_1 && minor == MINOR_0) {
        VERSION_DTLS_1_0
      } else {
        ProtocolVersion(major, minor)
      }
    }

    /**
     * Get protocol version value of the provided versions.
     * @param version textual version. e.g. "1.2".
     * @return protocol version
     */
    fun valueOf(version: String): ProtocolVersion {
      val split = version.split("\\.".toRegex())
      val major = 255 - Integer.parseInt(split[0])
      val minor = 255 - Integer.parseInt(split[1])
      return valueOf(major, minor)
    }
  }

  /**
   * Compares this protocol version to another one.
   *
   * **NOTE** that the comparison is done based on the _semantic_ version, i.e. DTLS protocol version 1.0 (represented as major 254, minor 255) is considered _lower_ than 1.2 (represented as major 254, minor 253) whereas the byte values representing version 1.0 are actually larger.
   * @param other the protocol version to compare to
   * @return _0_ if this version is exactly the same as the other version, _-1_ if this version is lower than the other version or _1_ if this version is higher than the other version.
   */
  override fun compareTo(other: ProtocolVersion): Int {
    if (this == other) {
      return 0
    }
    // Example, version 1.0 (254, 255) is smaller than version 1.2 (254, 253)
    return if (major == other.major) {
      other.minor.compareTo(minor)
    } else if (major < other.major) {
      1
    } else {
      -1
    }
  }

  override fun hashCode(): Int {
    val prime = 31
    var result = 1
    result = prime * result + major
    result = prime * result + minor
    return result
  }

  override fun equals(other: Any?): Boolean {
    return if (this === other) {
      true
    } else if (other == null) {
      false
    } else if (other !is ProtocolVersion) {
      false
    } else {
      major == other.major && minor == other.minor
    }
  }

  override fun toString(): String = "${255 - major}.${255 - minor}"
}
