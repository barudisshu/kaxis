/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.message.handshake

import io.kaxis.dtls.PskPublicInformation
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility

class EcdhPskClientKeyExchange : ECDHClientKeyExchange {
  companion object {
    private const val IDENTITY_LENGTH_BITS = 16 // opaque <0..2^16-1>;

    /**
     * Creates a new client key exchange instance from its byte representation.
     * @param reader reader for the binary encoding of the message.
     * @return created client key exchange message
     */
    fun fromReader(reader: DatagramReader): EcdhPskClientKeyExchange {
      val identityEncoded = reader.readVarBytes(IDENTITY_LENGTH_BITS)
      val identity = PskPublicInformation.fromByteArray(identityEncoded)
      val pointEncoded = readEncodedPoint(reader)
      return EcdhPskClientKeyExchange(identity, pointEncoded)
    }
  }

  /**
   * See [RFC 5489](https://tools.ietf.org/html/rfc5489#section-2).
   */
  val identity: PskPublicInformation

  /**
   * Creates a new key exchange message for an identity hint and a public key.
   * @param identity PSK identity as public information
   * @param encodedPoint ephemeral(短命的) public key as encoded point
   * @throws NullPointerException if either identity or clientPubicKey are `null`
   */
  constructor(identity: PskPublicInformation?, encodedPoint: ByteArray) : super(encodedPoint) {
    requireNotNull(identity) { "identity cannot be null" }
    this.identity = identity
  }

  /**
   * Write fragment to writer. Write the encoded point. Write the identity and encoded point.
   */
  override fun writeFragment(writer: DatagramWriter) {
    writer.writeVarBytes(identity, IDENTITY_LENGTH_BITS)
    super.writeFragment(writer)
  }

  override val messageLength: Int
    get() = 2 + identity.length() + super.messageLength

  override fun toString(indent: Int): String {
    return StringBuilder(super.toString(indent)).apply sb@{
      val indentation = Utility.indentation(indent + 1)
      this@sb.append(indentation).append("Encoded identity value: ")
      this@sb.append(identity).append(Utility.LINE_SEPARATOR)
    }.toString()
  }
}
