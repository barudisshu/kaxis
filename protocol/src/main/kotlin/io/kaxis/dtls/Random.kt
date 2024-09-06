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

import io.kaxis.Bytes
import io.kaxis.dtls.cipher.RandomManager
import io.kaxis.util.Utility
import java.util.*

class Random : Bytes {
  companion object {
    /**
     * Create byte array of 32 bytes initialized with random bytes and time stamp in the first 4 bytes.
     * @return byte array initialized with random bytes
     *
     */
    fun createBytes(): ByteArray {
      val randomBytes = createBytes(RandomManager.currentSecureRandom(), 32)

      // overwrite the first 4 bytes with the UNIX time
      val gmtUnixTime: Int = (System.currentTimeMillis() / 1000).toInt()
      randomBytes[0] = (gmtUnixTime shr 24).toByte()
      randomBytes[1] = (gmtUnixTime shr 16).toByte()
      randomBytes[2] = (gmtUnixTime shr 8).toByte()
      randomBytes[3] = gmtUnixTime.toByte()
      return randomBytes
    }
  }

  constructor() : this(createBytes())

  constructor(randomBytes: ByteArray) : super(randomBytes) {
    require(randomBytes.size == 32) { "Random bytes array's length must be 32" }
  }

  fun toString(indent: Int): String {
    val sb = StringBuilder()
    val randomBytes = byteArray
    // get the UNIX timestamp from the first 4 bytes
    val b0 = randomBytes[0].toInt()
    val b1 = randomBytes[1].toInt()
    val b2 = randomBytes[2].toInt()
    val b3 = randomBytes[3].toInt()

    val gmtUnixTime = ((0xFF and b0) shl 24) or ((0xFF and b1) shl 16) or ((0xFF and b2) shl 8) or (0xFF and b3)

    val date = Date(gmtUnixTime * 1000L)

    val indentation = Utility.indentation(indent)

    sb.append(indentation).append("GMT Unix Time: ").append(date).append(Utility.LINE_SEPARATOR)

    // output the remaining 28 random bytes
    val rand = randomBytes.copyOfRange(4, 32)
    sb.append(indentation).append("Random Bytes: ").append(Utility.byteArray2Hex(rand)).append(Utility.LINE_SEPARATOR)
    return sb.toString()
  }

  override fun toString(): String {
    return toString(0)
  }
}
