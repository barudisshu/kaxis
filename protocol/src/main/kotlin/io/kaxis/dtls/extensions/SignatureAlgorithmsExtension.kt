/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.extensions

import io.kaxis.dtls.SignatureAndHashAlgorithm
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility

/**
 * Implements the hello extension for signature and hash algorithms.
 */
class SignatureAlgorithmsExtension(
  val signatureAndHashAlgorithms: MutableList<SignatureAndHashAlgorithm>,
) : HelloExtension(ExtensionType.SIGNATURE_ALGORITHMS) {
  companion object {
    private const val LIST_LENGTH_BITS = 16

    private const val SIGNATURE_ALGORITHM_BITS = 16

    private const val SIGNATURE_BITS = 8

    private const val HASH_BITS = 8

    fun fromExtensionDataReader(extensionDataReader: DatagramReader): SignatureAlgorithmsExtension {
      val signatureAndHashAlgorithms =
        arrayListOf<SignatureAndHashAlgorithm>().apply sh@{
          val listLength = extensionDataReader.read(LIST_LENGTH_BITS)
          val rangeReader = extensionDataReader.createRangeReader(listLength)
          while (rangeReader.bytesAvailable()) {
            val hashId = rangeReader.read(HASH_BITS)
            val signatureId = rangeReader.read(SIGNATURE_BITS)
            this@sh.add(SignatureAndHashAlgorithm(hashId, signatureId))
          }
        }
      return SignatureAlgorithmsExtension(signatureAndHashAlgorithms)
    }
  }

  override fun toString(indent: Int): String {
    return StringBuilder(super.toString(indent)).apply sb@{
      val indentation = Utility.indentation(indent + 1)
      val indentation2 = Utility.indentation(indent + 2)
      this@sb.append(indentation).append("Signature Algorithms (").append(signatureAndHashAlgorithms.size)
        .append(" algorithms):").append(Utility.LINE_SEPARATOR)

      signatureAndHashAlgorithms.forEach { signatureAndHashAlgorithm ->
        this@sb.append(indentation2).append("Signature and Hash Algorithm: ").append(signatureAndHashAlgorithm)
          .append(Utility.LINE_SEPARATOR)
      }
    }.toString()
  }

  override val extensionLength: Int
    get() {
      // fixed: list length (2 bytes)
      // variable: number of signature algorithm * 2 (1 byte for signature algorithm, 1 byte for hash algorithm )
      return (
        (LIST_LENGTH_BITS / Byte.SIZE_BITS) +
          (signatureAndHashAlgorithms.size * (SIGNATURE_ALGORITHM_BITS / Byte.SIZE_BITS))
      )
    }

  override fun writeExtensionTo(writer: DatagramWriter) {
    val listLength = signatureAndHashAlgorithms.size * (SIGNATURE_ALGORITHM_BITS / Byte.SIZE_BITS)
    writer.write(listLength, LIST_LENGTH_BITS)

    signatureAndHashAlgorithms.forEach { signatureAndHashAlgorithm ->
      writer.write(signatureAndHashAlgorithm.hashAlgorithmCode, HASH_BITS)
      writer.write(signatureAndHashAlgorithm.signatureAlgorithmCode, SIGNATURE_BITS)
    }
  }
}
