/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.extensions

import io.kaxis.dtls.message.AlertMessage
import io.kaxis.exception.HandshakeException
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility
import java.util.*

/**
 * A container for one or more [HelloExtension]s.
 */
class HelloExtensions {
  companion object {
    const val OVERALL_LENGTH_BITS = 16

    /**
     * Create and read extensions.
     * @param reader the serialized extension
     * @return create extensions
     * @throws HandshakeException if the (supported) extension could not be de-serialized, e.g. due to
     * erroneous encoding etc. Or an extension type occurs more than once.
     */
    @Throws(HandshakeException::class)
    fun fromReader(reader: DatagramReader): HelloExtensions {
      val extensions = HelloExtensions()
      extensions.readFrom(reader)
      return extensions
    }
  }

  /**
   * The list of extensions.
   */
  private val extensions = arrayListOf<HelloExtension>()

  /**
   * Checks if this container actually holds any extensions.
   * @return `true`, if there are no extensions
   */
  fun isEmpty(): Boolean = extensions.isEmpty()

  /**
   * Calculate the lengths of the whole extension fragment. Includes the two bytes to encode the [extensionsLength] itself. [RFC 5246, 7.4.1.2](https://tools.ietf.org/html/rfc5246#section-7.4.1.2).
   *
   * ```
   * select (extensions_present) {
   * case false:
   *              struct {};
   * case true:
   *              Extension extensions<0..2^16-1>;
   * };
   * ```
   *
   * @return the length of the whole extension fragment. 0, if no extensions are used.
   */
  val length: Int
    get() {
      return if (extensions.isEmpty()) {
        0
      } else {
        extensionsLength + (OVERALL_LENGTH_BITS / Byte.SIZE_BITS)
      }
    }

  /**
   * Calculate the length of all extensions.
   */
  val extensionsLength: Int
    get() {
      var length = 0
      extensions.forEach { extension ->
        length += extension.length
      }
      return length
    }

  operator fun <T : HelloExtension> get(type: HelloExtension.ExtensionType?): T? {
    return getExtension(type)
  }

  /**
   * Gets a hello extension of a particular type.
   * @param type the type of extension or replacement type
   * @return the extension, or `null`, if no extension of the given type nor replacement type is present
   * @throws NullPointerException if type is `null`
   */
  @Suppress("UNCHECKED_CAST", "kotlin:S6531")
  fun <T : HelloExtension> getExtension(type: HelloExtension.ExtensionType?): T? {
    requireNotNull(type) { "Extension type must not be null!" }
    var replacement: HelloExtension? = null
    extensions.forEach { ext ->
      if (type == ext.type) {
        return ext as T
      } else if (type == ext.type.replacement) {
        replacement = ext
      }
    }
    return replacement as? T
  }

  /**
   * Add hello extension.
   * @param extension hello extension to add
   */
  fun addExtension(extension: HelloExtension?) {
    if (extension != null) {
      if (getExtension(extension.type) as HelloExtension? == null) {
        this.extensions += (extension)
      } else {
        throw IllegalArgumentException("Hello Extension of type ${extension.type} already added!")
      }
    }
  }

  operator fun plus(extension: HelloExtension?) = addExtension(extension)

  /**
   * Gets the textual presentation of this message.
   * @param indent line indentation
   * @return textual presentation
   */
  fun toString(indent: Int): String {
    return StringBuilder().apply sb@{
      val indentation = Utility.indentation(indent)
      this@sb.append(indentation).append("Extensions Length: ").append(extensionsLength).append(" bytes")
        .append(Utility.LINE_SEPARATOR)
      extensions.forEach { ext ->
        this@sb.append(ext.toString(indent + 1))
      }
    }.toString()
  }

  override fun toString(): String {
    return toString(0)
  }

  /**
   * Write extensions.
   * @param writer writer to write extensions to.
   */
  fun writeTo(writer: DatagramWriter) {
    if (extensions.isNotEmpty()) {
      writer.write(extensionsLength, OVERALL_LENGTH_BITS)
      extensions.forEach { extension ->
        extension.writeTo(writer)
      }
    }
  }

  /**
   * Read extensions from reader.
   * @param reader the serialized extensions
   * @throws HandshakeException if the (supported) extension could not be de-serialized, e.g. due to
   * erroneous encoding etc. Or a extension type occurs more than once.
   */
  @Throws(HandshakeException::class)
  fun readFrom(reader: DatagramReader) {
    if (reader.bytesAvailable()) {
      try {
        val length = reader.read(OVERALL_LENGTH_BITS)
        val rangeReader = reader.createRangeReader(length)
        while (rangeReader.bytesAvailable()) {
          val extension = HelloExtension.readFrom(rangeReader)
          if (extension != null) {
            if (getExtension(extension.type) as HelloExtension? == null) {
              addExtension(extension)
            } else {
              throw HandshakeException(
                AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.DECODE_ERROR),
                "Hello message contains extension ${extension.type} more than once!",
              )
            }
          }
        }
      } catch (ex: IllegalArgumentException) {
        throw HandshakeException(
          AlertMessage(
            AlertMessage.AlertLevel.FATAL,
            AlertMessage.AlertDescription.DECODE_ERROR,
          ),
          "Hello message contained malformed extensions, ${ex.message}",
        )
      }
    }
  }
}
