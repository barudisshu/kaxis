/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

@file:JvmName("Utility")

package io.kaxis.util

import io.kaxis.Bytes
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.io.IOException
import java.net.*
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CoderResult
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.PublicKey
import java.security.cert.Certificate
import java.util.regex.Pattern
import kotlin.experimental.or

/**
 * String utility (as there are so many already out).
 */
object Utility {
  const val NO_SEPARATOR: Char = 0.toChar()

  /**
   * Regex pattern for valid hostnames.
   */
  private val HOSTNAME_PATTERN: Pattern =
    Pattern.compile(
      "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$",
    )

  private val IP_PATTERN: Pattern =
    Pattern
      .compile("^(\\[[0-9a-fA-F:]+(%\\w+)?\\]|[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})$")

  /**
   * Workaround to support android API 16-18.
   */
  @JvmField
  val LINE_SEPARATOR: String = System.getProperty("line.separator", "\n")

  /**
   * Flag indicating, that [InetSocketAddress] supports [InetSocketAddress.getHostString]
   */
  @JvmField
  val SUPPORT_HOST_STRING: Boolean =
    try {
      val method = InetSocketAddress::class.java.getMethod("getHostString")
      true
    } catch (e: NoSuchMethodException) {
      // android before API 18
      false
    }

  private val TABS: Array<String> = Array(10) { _ -> "\t" }

  /**
   * Lookup table for hexadecimal digits.
   */
  @JvmField
  val BIN_TO_HEX_ARRAY = "0123456789ABCDEF".toCharArray()

  /**
   * Check if private IP.
   */
  @JvmStatic
  fun isPrivateIp(ipAddr: String): Boolean {
    try {
      val address = InetAddress.getByName(ipAddr)
      return address.isSiteLocalAddress || address.isLoopbackAddress || address.isLinkLocalAddress ||
        isCarrierGradeNatIp(
          address,
        )
    } catch (e: UnknownHostException) {
      // ignore parse exception
    }

    return false
  }

  /**
   * Check if carrier nat IP.
   *
   * Example:
   * ```
   * CarrierGradeNAT: 100.64.0.0 ~ 100.127.255.255
   * ```
   */
  @JvmStatic
  fun isCarrierGradeNatIp(address: InetAddress): Boolean {
    val byteAddr = address.address
    val oct1 = byteAddr[0].toInt()
    // Private IPs used for carrier grade NAT
    if ((oct1 and 0xff) == 100) {
      val octet2 = byteAddr[1].toInt()
      return (octet2 and 0xff) >= 64 && (octet2 and 0xff) < 128
    }
    return false
  }

  /**
   * Get host string of inet socket address.
   * @return host string.
   */
  @JvmStatic
  fun toHostString(socketAddress: InetSocketAddress): String =
    if (SUPPORT_HOST_STRING) {
      socketAddress.hostString
    } else {
      val address = socketAddress.address
      if (address != null) {
        val textAddress = address.toString()
        if (textAddress.startsWith("/")) {
          // unresolved, return literal IP
          textAddress.substring(1)
        } else {
          // resolved, safe to call getHostName
          address.hostName
        }
      } else {
        socketAddress.hostName
      }
    }

  /**
   * Get indentation-prefix.
   * @param indentIndex indent
   * @return indentation prefix
   */
  @JvmStatic
  fun indentation(indentIndex: Int): String =
    if (indentIndex < 0) {
      ""
    } else if (indentIndex >= TABS.size) {
      TABS[TABS.size - 1]
    } else {
      TABS[indentIndex]
    }

  /**
   * Convert hexadecimal String into decoded character array. Intended to be used for passwords.
   * @param hex hexadecimal string. e.g. "4130010A"
   * @return character array with decoded hexadecimal input parameter. e.g. `char[]{'A','0',0x01,'\n']`
   * @throws IllegalStateException if the parameter length is odd or contains non hexadecimal characters.
   */
  @JvmStatic
  fun hex2CharArray(hex: String?): CharArray? {
    if (hex == null) {
      return null
    }
    var length = hex.length
    require((1 and length) == 0) { "'$hex' has odd length!" }
    length /= 2
    val result = CharArray(length)

    var indexDest = 0
    var indexSrc = 0
    while (indexDest < length) {
      var digit = Character.digit(hex[indexSrc], 16)
      require(digit >= 0) { "'$hex' digit $indexSrc is not hexadecimal!" }
      result[indexDest] = (digit shl 4).toChar()
      indexSrc++

      digit = Character.digit(hex[indexSrc], 16)
      require(digit >= 0) { "'$hex' digit $indexSrc is not hexadecimal!" }
      result[indexDest] = (result[indexDest].code or digit.toChar().code).toChar()
      indexSrc++

      indexDest++
    }
    return result
  }

  /**
   * Character array to hexadecimal string.
   * @param charArray character array.
   * @return hexadecimal string, or `null`, if provided character array is `null`.
   */
  @JvmStatic
  fun charArray2hex(charArray: CharArray?): String? =
    charArray?.let {
      val length = it.size
      StringBuilder(length * 2).apply sb@{
        for (index in 0..<length) {
          val value = it[index].code and 0xFF
          this@sb.append(BIN_TO_HEX_ARRAY[value ushr 4])
          this@sb.append(BIN_TO_HEX_ARRAY[value and 0x0F])
        }
      }.toString()
    }

  /**
   * Convert hexadecimal String into decoded byte array.
   * @param hex hexadecimal string. e.g. "4130010A"
   * @return byte array with decoded hexadecimal input parameter.
   * @throws IllegalArgumentException if the parameter length is odd or contains non hexadecimal characters.
   * @see byteArray2Hex
   */
  @JvmStatic
  fun hex2ByteArray(hex: String?): ByteArray? =
    hex?.let {
      var length = it.length
      require((1 and length) == 0) { "'$hex' has odd length!" }
      length /= 2
      val result = ByteArray(length)
      var indexDest = 0
      var indexSrc = 0
      while (indexDest < length) {
        var digit = Character.digit(hex[indexSrc], 16)
        require(digit >= 0) { "'$hex' digit $indexSrc is not hexadecimal!" }
        result[indexDest] = (digit shl 4).toByte()
        indexSrc++

        digit = Character.digit(hex[indexSrc], 16)
        require(digit >= 0) { "'$hex' digit $indexSrc is not hexadecimal!" }
        result[indexDest] = result[indexDest] or digit.toByte()
        indexSrc++

        indexDest++
      }
      result
    }

  /**
   * Byte array to hexadecimal string without separator.
   * @param byteArray byte array to be converted to string.
   * @return hexadecimal string, e.g "0142A3". `null`, if the provided byte array is `null`. "", if provided byte array is empty.
   * @see hex2ByteArray
   */
  @JvmStatic
  fun byteArray2Hex(byteArray: ByteArray?): String? =
    byteArray?.let { if (it.isEmpty()) "" else byteArray2HexString(it, NO_SEPARATOR, 0) }

  /**
   * Byte array to hexadecimal display string.
   * All bytes are converted without separator.
   * @param byteArray byte array to be converted to string.
   * @return hexadecimal string, e.g "0145A4", "--", if byte array is `null` or empty.
   */
  @JvmStatic
  fun byteArray2HexString(byteArray: ByteArray?): String = byteArray2HexString(byteArray, NO_SEPARATOR, 0)

  /**
   * Byte array to hexadecimal display string.
   * @param byteArray byte array to be converted to string
   * @param sep separator. If [NO_SEPARATOR], then no separator is used between the bytes.
   * @param max maximum bytes to be converted. 0 to convert all bytes.
   * @return hexadecimal string, e.g "01:45:A4", if ':' is used as separator. "--", if byte array is `null` or empty.
   */
  @JvmStatic
  fun byteArray2HexString(
    byteArray: ByteArray?,
    sep: Char,
    max: Int,
  ): String =
    if (byteArray?.isNotEmpty() != null) {
      val maximum = if (max == 0 || max > byteArray.size) byteArray.size else max
      StringBuilder(maximum * (if (sep == NO_SEPARATOR) 2 else 3)).apply sb@{
        for (index in 0..<maximum) {
          val value = byteArray[index].toInt() and 0xFF
          this@sb.append(BIN_TO_HEX_ARRAY[value ushr 4])
          this@sb.append(BIN_TO_HEX_ARRAY[value and 0x0F])
          if (sep != NO_SEPARATOR && index < max - 1) {
            this@sb.append(sep)
          }
        }
      }.toString()
    } else {
      "--"
    }

  @JvmStatic
  fun byteArray2HexStringDump(byteArray: ByteArray?): String =
    byteArray2HexStringDump(byteArray, 0, byteArray?.size ?: 0)

  @JvmStatic
  fun byteArray2HexStringDump(
    byteArray: ByteArray?,
    offset: Int,
    length: Int,
  ): String {
    return HexUtil.prettyHexDump(byteArray, offset, length)
  }

  /**
   * Decode base64 string into byte array.
   * Add padding, if missing.
   * **Note**: Function will change with the next major release to throw an [IllegalArgumentException] instead of returning an empty array, if invalid characters are contained.
   * @param base64 base64 string
   * @return byte array. empty, if provided string could not be decoded.
   * @throws IllegalArgumentException if the length is invalid for base64.
   */
  @JvmStatic
  fun base64ToByteArray(base64: String): ByteArray {
    var pad = base64.length % 4
    val append =
      if (pad > 0) {
        pad = 4 - pad
        when (pad) {
          1 -> "="
          2 -> "=="
          else ->
            throw IllegalArgumentException("'$base64' invalid base64!")
        }
      } else {
        null
      }
    return try {
      Base64.decode(if (append == null) base64 else base64 + append)
    } catch (e: IOException) {
      Bytes.EMPTY_BYTES
    }
  }

  /**
   * Decode base 64 char array into byte array.
   * Alternative to [base64ToByteArray] for converting credentials. A char array could be cleared after usage, while a String may only get garbage collected. Add padding, if missing.
   * @param base64 base64 char array
   * @return byte array.
   * @throws IllegalArgumentException if the length is invalid for base 64 or character is out of the supported character set of base 64.
   */
  fun base64ToByteArray(base64: CharArray): ByteArray {
    var pad = base64.size % 4
    if (pad > 0) {
      pad = 4 - pad
      require(pad == 1 || pad == 2) { "'${String(base64)}' invalid bas64!" }
    }
    var index = 0
    val data64 = ByteArray(base64.size + pad)
    while (index < base64.size) {
      val b: Char = base64[index]
      require(b.code <= 127) { "'${String(base64)}' has invalid base64 char '$b'!" }
      data64[index] = b.code.toByte()
      index++
    }
    while (pad > 0) {
      --pad
      data64[index++] = '='.code.toByte()
    }
    try {
      return Base64.decode(data64)
    } catch (e: IOException) {
      throw IllegalArgumentException(e.message)
    }
  }

  /**
   * Encode byte array into base64 string.
   * @param bytes byte array
   * @return base64 string
   */
  @JvmStatic
  fun byteArrayToBase64(bytes: ByteArray): String = Base64.encodeBytes(bytes)

  /**
   * Encode byte array into base64 char array.
   * @param bytes byte array
   * @return base64 char array
   */
  @JvmStatic
  fun byteArrayToBase64CharArray(bytes: ByteArray): CharArray {
    val base64 = Base64.encodeBytesToBytes(bytes)
    val result = CharArray(base64.size)
    for (index in base64.indices) {
      result[index] = base64[index].toInt().toChar()
    }
    Bytes.clear(base64)
    return result
  }

  /**
   * Truncate provided string.
   * @param text string to be truncated, if length is over the provided maxLength
   * @param maxLength maximum length of string. (0 doesn't truncate)
   * @return truncated or original string
   */
  @JvmStatic
  fun trunc(
    text: String?,
    maxLength: Int,
  ): String? {
    if (text != null && maxLength > 0 && maxLength < text.length) {
      return text.substring(0, maxLength)
    }
    return text
  }

  /**
   * Remove tail from builder's
   * If provided tail doesn't match, the provided builder is unchanged.
   * @param builder builder to remove tail
   * @param tail tail to remove.
   * @return `true`, if the provided tail has been removed, `false`, if the build is left unchanged.
   * @throws NullPointerException if one of the provided arguments is `null`.
   */
  @JvmStatic
  fun truncateTail(
    builder: StringBuilder?,
    tail: String?,
  ): Boolean {
    if (builder == null) {
      throw NullPointerException("Builder must not be null!")
    }
    if (tail == null) {
      throw NullPointerException("Tail must not be null!")
    }
    var truncated = false
    val tailLength = tail.length
    if (tailLength > 0) {
      val end = builder.length - tailLength
      if (end > 0) {
        truncated = true
        for (index in 0..<tailLength) {
          if (builder[index + end] != tail[index]) {
            truncated = false
            break
          }
        }
        if (truncated) {
          builder.setLength(end)
        }
      }
    }
    return truncated
  }

  /**
   * Remove tail from text.
   * If provided tail doesn't match the tail of the text, the text is returned unchanged.
   * @param text text to remove tail
   * @param tail tail to remove
   * @return text with tail removed, if matching, Otherwise the provided text.
   * @throws NullPointerException if one of the provided arguments is `null`.
   */
  @JvmStatic
  fun truncateTail(
    text: String?,
    tail: String?,
  ): String {
    if (text == null) {
      throw NullPointerException("Text must not be null!")
    }
    if (tail == null) {
      throw NullPointerException("Tail must not be null!")
    }
    if (tail.isNotBlank() && text.endsWith(tail)) {
      return text.substring(0, text.length - tail.length)
    }
    return text
  }

  /**
   * Get display text for Certificate.
   * @param cert certificate
   * @return display text
   */
  @JvmStatic
  fun toDisplayString(cert: Certificate): String {
    var indentIndex = 0
    val lines = cert.toString().split('\n')
    val text = StringBuilder()
    for (line in lines.map(String::trim)) {
      if (line.isNotBlank()) {
        var indent = indentDelta(line)
        if (indent < 0 && line.length == 1) {
          indentIndex += indent
          indent = 0
        }
        text.append(indentation(indentIndex)).append(line).append(LINE_SEPARATOR)
        indentIndex += indent
      } else {
        text.append(LINE_SEPARATOR)
      }
    }
    return text.toString()
  }

  /**
   * Get display text for public key.
   * @param publicKey public key
   * @return display text
   */
  @JvmStatic
  fun toDisplayString(publicKey: PublicKey): String = publicKey.toString().replace("\n\\s+", "\n")

  /**
   * Get socket address as string for logging.
   * @param address socket address to be converted to string
   * @return the host string, if available, separated by "/", appended by the host address, ":" and the port. For "any addresses", "port#port" is returned. and `null`, if address is `null`.
   */
  @JvmStatic
  fun toDisplayString(address: InetSocketAddress?): String? {
    if (address == null) return null
    val addr = address.address
    if (addr != null && addr.isAnyLocalAddress) {
      return "port ${address.port}"
    }
    var name = if (SUPPORT_HOST_STRING) toHostString(address) else ""
    val host = if (addr != null) toString(addr) else "<unresolved>"
    if (name == host) {
      name = ""
    } else {
      name += "/"
    }
    return if (address.address is Inet6Address) {
      name + "[" + host + "]:" + address.port
    } else {
      name + host + ":" + address.port
    }
  }

  /**
   * Convert UTF-8 data into display string.
   *
   * If none-printable data is contained, the data is converted to a hexa-decimal string. If the UTF-8 string exceeds the limit, it's truncated and the length is appended. If a hexa-decimal string is returned and the data length exceeds the limit, the data is truncated and the length is appended.
   * @param data data to convert
   * @param limit limit of result. Either limits the UTF-8 string, or the data for the hexa-decimal string.
   * @return display string
   */
  @JvmStatic
  fun toDisplayString(
    data: ByteArray?,
    limit: Int,
  ): String {
    if (data == null) {
      return "<no data>"
    } else if (data.isEmpty()) {
      return "<empty data>"
    }
    if (data.size < limit) return toDisplayString(data, data.size)
    var text = true
    for (b in data) {
      if (' '.code > b) {
        if (b.toInt().toChar() == '\t' || b.toInt().toChar() == '\n' || b.toInt().toChar() == '\r') continue
        text = false
        break
      }
    }
    if (text) {
      val decoder = StandardCharsets.UTF_8.newDecoder()
      decoder.onMalformedInput(CodingErrorAction.REPORT)
      decoder.onUnmappableCharacter(CodingErrorAction.REPORT)
      val inputStream = ByteBuffer.wrap(data)
      val outputStream = CharBuffer.allocate(limit)
      val result = decoder.decode(inputStream, outputStream, true)
      decoder.flush(outputStream)
      outputStream.flip()
      if (CoderResult.OVERFLOW == result) {
        return "\"$outputStream\".. ${data.size} bytes"
      } else if (!result.isError) {
        return "\"$outputStream\""
      }
    }
    var hex = byteArray2HexString(data, ' ', limit)
    if (data.size > limit) {
      hex += "..${data.size} bytes"
    }
    return hex
  }

  /**
   * Get address as string for logging.
   * @param address address to be converted to string
   * @return the host address, or `null`, if address is `null`.
   */
  @JvmStatic
  fun toString(address: InetAddress?): String? = address?.hostAddress

  /**
   * Get socket address as string for logging.
   * @param address socket address to be converted to string
   * @return the host string, if available, otherwise the host address, both appended with ":" and the port. Or `null`, if address is `null`.
   */
  @JvmStatic
  fun toString(address: InetSocketAddress?): String? {
    if (address == null) return null
    val host =
      if (SUPPORT_HOST_STRING) {
        toHostString(address)
      } else {
        val addr = address.address
        if (addr != null) {
          toString(addr)
        } else {
          "<unresolved>"
        }
      }
    return if (address.address is Inet6Address) {
      "[" + host + "]:" + address.port
    } else {
      host + ":" + address.port
    }
  }

  /**
   * Get socket address as string for logging.
   * @param address socket address to be converted to string.
   * @return the socket address as string, or `null`, if address is `null`.
   * @see toString(InetSocketAddress?)
   */
  @JvmStatic
  fun toString(address: SocketAddress?): String? {
    if (address == null) return null
    if (address is InetSocketAddress) return toString(address)
    return address.toString()
  }

  /**
   * Returns a "lazy message supplier" for socket address.
   *
   * Converts the provided socket address into a display string on calling [toString] on the returned object. Emulates the MessageSupplier idea of log4j.
   * @param address address to log.
   * @return "lazy message supplier"
   */
  @JvmStatic
  fun toLog(address: SocketAddress?): Any? {
    if (address == null) return null
    return object : Any() {
      override fun toString(): String {
        if (address is InetSocketAddress) return toDisplayString(address)!!
        return address.toString()
      }
    }
  }

  /**
   * Checks if a given string is a valid host name as defined by [RFC 1123](https://tools.ietf.org/html/rfc1123).
   * @param hostName the name to check
   * @return `true` if the name is a valid host name.
   */
  @JvmStatic
  fun isValidHostName(hostName: String?): Boolean {
    return (hostName != null) && HOSTNAME_PATTERN.matcher(hostName).matches()
  }

  /**
   * Checks if a given string is a literal IP address.
   * @param address address to check
   * @return `true` if the address is a literal IP address.
   */
  @JvmStatic
  fun isLiteralIpAddress(address: String?): Boolean {
    return (address != null) && IP_PATTERN.matcher(address).matches()
  }

  /**
   * Get URI hostname from address.
   *
   * Apply workaround for JDK-8199396.
   *
   * **Note**: a "%" in a IPv6 address is replaced by the encoded form with "%25".
   * @param address address
   * @return uri hostname
   * @throws NullPointerException if address is `null`.
   * @throws URISyntaxException if address could not be converted into URI hostname.
   */
  @JvmStatic
  @Throws(URISyntaxException::class)
  @Suppress("kotlin:S3776")
  fun getUriHostname(address: InetAddress?): String {
    requireNotNull(address) { "address must not be null!" }
    var host = address.hostAddress
    if (address is Inet6Address && (address.scopedInterface != null || address.scopeId > 0)) {
      val pos = host.indexOf('%')
      if (pos > 0 && pos + 1 < host.length) {
        val separator = "%25"
        var scope = host.substring(pos + 1)
        val hostAddress = host.substring(0, pos)
        host = hostAddress + separator + scope
        try {
          URI(null, null, host, -1, null, null, null)
        } catch (e: URISyntaxException) {
          // work-around for openjdk bug JDK-8199396.
          // some characters are not supported for the ipv6 scope.
          scope = scope.replace("[-._~]", "")
          if (scope.isEmpty()) {
            host = hostAddress
          } else {
            host = hostAddress + separator + scope
            try {
              URI(null, null, host, -1, null, null, null)
            } catch (e2: URISyntaxException) {
              throw e
            }
          }
        }
      }
    }

    return host
  }

  /**
   * Normalize logging tag.
   * The normalized tag is either a empty string "", or terminated by a space ' '.
   * @param tag tag to be normalized. `null` will be normalized to a empty string "".
   * @return normalized tag. Either a empty string "", or terminated by a space ' '
   */
  @JvmStatic
  fun normalizeLoggingTag(tag: String?): String {
    if (tag == null) {
      normalizeLoggingTag("")
    } else if (tag.isNotEmpty() && !tag.endsWith(" ")) {
      normalizeLoggingTag("$tag ")
    }
    return tag!!
  }

  /**
   * Get indent delta for provided lines.
   * Counts `'[' (+1) and ']'(-1)`.
   * @param line line
   * @return indent change.
   */
  private fun indentDelta(line: String): Int {
    var index = 0
    var i = line.length
    while (i > 0) {
      --i
      val c = line[i]
      if (c == '[') {
        ++index
      } else if (c == ']') {
        --index
      }
    }
    if (index != 0 && line.matches("\\d+:\\s+.*".toRegex())) {
      // escape hex-dumps
      return 0
    }
    return index
  }

  /**
   * checks, whether the set contains the value, or not.
   *
   * The check is done using [String.equals].
   * @param set set of strings.
   * @param value value to match
   * @return `true`, if value is contained in set, `false`, otherwise.
   */
  @JvmStatic
  fun containsIgnoreCase(
    set: Array<String>,
    value: String?,
  ): Boolean {
    for (item in set) {
      if (item.equals(value, true)) return true
    }
    return false
  }

  /**
   * Get configuration value.
   *
   * Try first [System.getenv], if that returns `null` or an empty value, then return [System.getProperty].
   * @param name the name of the configuration value.
   * @return the value, or `null`, if neither [System.getenv] nor [System.getProperty] returns a value.
   */
  @JvmStatic
  fun getConfiguration(name: String): String? {
    val value = System.getenv(name)
    if (value.isNullOrEmpty()) {
      return System.getProperty(name) ?: value
    }
    return value
  }

  /**
   * Get long configuration value.
   *
   * Try first [System.getenv], if that returns `null` or an empty value, then return [System.getProperty] as long.
   * @param name the name of the configuration value.
   * @return the long value, or `null`, if neighter [System.getenv] nor [System.getProperty] returns a value.
   */
  @JvmStatic
  fun getConfigurationLong(name: String): Long? {
    val value = getConfiguration(name)
    if (!value.isNullOrEmpty()) {
      try {
        return value.toLong()
      } catch (ignored: NumberFormatException) {
        // NOSONAR
      }
    }
    return null
  }

  /**
   * Get boolean configuration value.
   *
   * Try first [System.getenv], if that returns `null` or an empty value, then return [System.getProperty] as Boolean.
   * @param name the name of the configuration value.
   * @return the boolean value, or `null`, if neither [System.getenv] nor [System.getProperty] returns a value.
   */
  @JvmStatic
  fun getConfigurationBoolean(name: String): Boolean {
    val value = getConfiguration(name)
    return value.toBoolean()
  }

  /**
   * Read file.
   * @param file file to read
   * @param defaultText default text
   * @return text contained in file, or defaultText, if file could not be read.
   */
  @JvmStatic
  fun readFile(
    file: File,
    defaultText: String,
  ): String {
    var content = defaultText
    if (file.canRead()) {
      FileReader(file, StandardCharsets.UTF_8).use { reader ->
        val lineReader = BufferedReader(reader)
        content = lineReader.readLine()
        lineReader.close()
      }
    }
    return content
  }
}
