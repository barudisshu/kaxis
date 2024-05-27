/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.extensions

import io.kaxis.dtls.CertificateType
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.util.*

abstract class CertificateTypeExtension : HelloExtension {
  companion object {
    private val LOGGER: Logger = LoggerFactory.getLogger(CertificateTypeExtension::class.java)

    protected const val LIST_FIELD_LENGTH_BITS = 8
    protected const val EXTENSION_TYPE_BITS = 8

    val EMPTY = mutableListOf<CertificateType>()

    val DEFAULT_X509 = asList(CertificateType.X_509)

    fun asList(certificateType: CertificateType): MutableList<CertificateType> {
      return arrayListOf(certificateType)
    }
  }

  val isClientExtension: Boolean

  /**
   * The list contains at least one certificate type (if one detected that should be server-side).
   */
  val certificateTypes: List<CertificateType>

  /**
   * Get head of list certificate type.
   */
  val certificateType: CertificateType
    get() = certificateTypes[0]

  fun contains(type: CertificateType) = certificateTypes.contains(type)

  /**
   * Get list with common certificate types.
   * @param supportedCertificateTypes list of supported certificate types
   * @return list of certificate types, which are included in this extension and in the provided list. The order is
   * defined by the order in this extension
   */
  fun getCommonCertificateTypes(supportedCertificateTypes: List<CertificateType>): MutableList<CertificateType> {
    return arrayListOf<CertificateType>().apply common@{
      certificateTypes.forEach {
        if (supportedCertificateTypes.contains(it)) {
          this@common.add(it)
        }
      }
    }
  }

  /**
   * Constructs a certificate type extension with a list of supported certificate types, or a selected certificate
   * type chosen by the server.
   * @param type the type of the extension.
   * @param extensionDataReader datagram reader.
   * @throws NullPointerException if extension data is `null`
   * @throws IllegalArgumentException if extension data is empty or no certificate type is contained.
   *
   */
  constructor(type: ExtensionType, extensionDataReader: DatagramReader?) : super(type) {
    requireNotNull(extensionDataReader) { "extension data must not be null!" }
    require(extensionDataReader.bytesAvailable()) { "extension data must not be empty!" }
    // the selected certificate would be a single byte.
    // the supported list is longer
    this.isClientExtension = extensionDataReader.bitsLeft() > Byte.SIZE_BITS
    val types: List<CertificateType>
    if (isClientExtension) {
      // an extension containing a list of preferred certificate types
      // is at least 2 bytes long (1 byte length, 1 byte type)
      val length = extensionDataReader.read(LIST_FIELD_LENGTH_BITS)
      types = ArrayList(length)
      val rangeReader = extensionDataReader.createRangeReader(length)
      while (rangeReader.bytesAvailable()) {
        val typeCode = rangeReader.read(EXTENSION_TYPE_BITS)
        val certificateType = CertificateType.getTypeFromCode(typeCode)
        if (certificateType != null) {
          types.add(certificateType)
        } else {
          // client indicates a preference for an unknown certificate type
          LOGGER.debug(
            "Client indicated preference for unknown {} certificate type code [{}]",
            if (type == ExtensionType.CLIENT_CERT_TYPE) "client" else "server",
            typeCode,
          )
        }
      }
      require(types.isNotEmpty()) { "Empty client certificate types!" }
    } else {
      // an extension containing the negotiated certificate type is exactly 1 byte long
      val typeCode = extensionDataReader.read(EXTENSION_TYPE_BITS)
      val certificateType = CertificateType.getTypeFromCode(typeCode)
      if (certificateType != null) {
        types = asList(certificateType)
      } else {
        // server selected a certificate type that is unknown to this client
        LOGGER.debug(
          "Server selected an unknown {} certificate type code [{}]",
          if (type == ExtensionType.CLIENT_CERT_TYPE) "client" else "server",
          typeCode,
        )
        throw IllegalArgumentException("unknown certificate type code $typeCode !")
      }
    }
    certificateTypes = Collections.unmodifiableList(types)
  }

  /**
   * Constructs a client-side certificate type extension with a list of supported certificate types.
   * @param type the type of the extension.
   * @param certificateTypes the list of supported certificate types.
   * @throws NullPointerException if certificate types is `null`.
   * @throws IllegalArgumentException if certificate types is empty.
   */
  constructor(type: ExtensionType, certificateTypes: List<CertificateType>?) : super(type) {
    requireNotNull(certificateTypes) { "certificate types must not be null!" }
    require(certificateTypes.isNotEmpty()) { "certificate types data must not be empty!" }
    this.isClientExtension = true
    this.certificateTypes = certificateTypes
  }

  /**
   * Constructs a server-side certificate type extension with a supported certificate type.
   * @param type the type of the extension
   * @param certificateType the supported certificate type.
   * @throws NullPointerException if certificate type is `null`.
   */
  constructor(type: ExtensionType, certificateType: CertificateType?) : super(type) {
    requireNotNull(certificateType) { "certificate type must not be null!" }
    this.isClientExtension = false
    this.certificateTypes = asList(certificateType)
  }

  fun toString(
    indent: Int,
    side: String,
  ): String {
    return StringBuilder(super.toString(indent)).apply sb@{
      val indentation = Utility.indentation(indent + 1)
      if (isClientExtension) {
        this@sb.append(indentation).append(side).append(" certificate types: (").append(certificateTypes.size)
          .append(" types)").append(Utility.LINE_SEPARATOR)
        val indentation2 = Utility.indentation(indent + 2)
        certificateTypes.forEach { type ->
          this@sb.append(indentation2).append(side).append(" certificate type: ").append(type)
            .append(Utility.LINE_SEPARATOR)
        }
      } else {
        this@sb.append(indentation).append(side).append(" certificate type: ").append(certificateType)
          .append(Utility.LINE_SEPARATOR)
      }
    }.toString()
  }

  override val extensionLength: Int
    get() {
      return if (isClientExtension) {
        // fixed: the list length field (1 byte)
        // each certificate type in the list uses 1 byte
        1 + certificateTypes.size
      } else {
        // fixed: the certificate type (1 byte)
        1
      }
    }

  override fun writeExtensionTo(writer: DatagramWriter) {
    if (isClientExtension) {
      // write number of certificate types
      writer.write(certificateTypes.size, LIST_FIELD_LENGTH_BITS)
      // write one byte for each certificate type
      certificateTypes.forEach { type ->
        writer.write(type.code, EXTENSION_TYPE_BITS)
      }
    } else {
      // we assume the list contains exactly one element
      writer.write(certificateType.code, EXTENSION_TYPE_BITS)
    }
  }
}
