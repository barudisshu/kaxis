/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.auth

import io.kaxis.util.Asn1DerDecoder
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.SerializationUtil
import java.security.GeneralSecurityException
import java.security.Principal

/**
 * A helper for serializing and deserializing principals supported by Kaxis.
 */
object PrincipalSerializer {
  private const val PSK_HOSTNAME_LENGTH_BITS = 16
  private const val PSK_IDENTITY_LENGTH_BITS = 16

  /**
   * Serializes a principal to a byte array based on the plain text encoding defined in [RFC 5077, Section 4](https://tools.ietf.org/html/rfc5077#section-4).
   *
   * RFC 5077 does not explicitly define support for _RawPublicKey_ based client authentication. However, it
   * supports the addition of arbitrary authentication mechanisms by extending the _ClientAuthentication Type_
   * which we do as follows:
   *
   * ```
   * enum {
   *  anonymous(0),
   *  certificate_based(1),
   *  psk(2),
   *  raw_public_key(255)
   * } ClientAuthenticationType
   *
   * struct {
   *  ClientAuthenticationType client_authentication_type;
   *  select (ClientAuthenticationType) {
   *    case anonymous:
   *      struct {};
   *    case psk:
   *      opaque psk_identity<0..2^16-1>;
   *    case certificate_based:
   *      DER ASN.1Cert certificate_list<0..2^24-1>;
   *    case raw_public_key:
   *      DER ASN.1_subjectPublicKeyInfo<1..2^24-1>;  // as defined in RFC 7250
   *  };
   * }
   * ```
   *
   * psk_identity may be scoped by server name indication. To distinguish scoped and plain psk_identity, the
   * first byte in the `opaque psk_identity` indicates a scoped identity with 1, or a plain identity with 0.
   * @param principal The principal to serialize.
   * @param writer The writer to serialize to.
   * @throws NullPointerException if the writer is `null`
   */
  fun serialize(
    principal: Principal?,
    writer: DatagramWriter?,
  ) {
    requireNotNull(writer) { "Writer must not be null" }
    if (principal == null) {
      writer.writeByte(ClientAuthenticationType.ANONYMOUS.code)
    } else if (principal is PreSharedKeyIdentity) {
      serializeIdentity(principal, writer)
    } else if (principal is RawPublicKeyIdentity) {
      serializeSubjectInfo(principal, writer)
    } else if (principal is X509CertPath) {
      serializeCertChain(principal, writer)
    } else {
      throw IllegalArgumentException("unsupported principal type: ${principal.javaClass.name}")
    }
  }

  private fun serializeIdentity(
    principal: PreSharedKeyIdentity,
    writer: DatagramWriter,
  ) {
    writer.writeByte(ClientAuthenticationType.PSK.code)
    if (principal.isScopedIdentity) {
      writer.writeByte(1) // scoped
      SerializationUtil.write(writer, principal.virtualHost, PSK_HOSTNAME_LENGTH_BITS)
      SerializationUtil.write(writer, principal.identity, PSK_IDENTITY_LENGTH_BITS)
    } else {
      writer.writeByte(0) // plain
      SerializationUtil.write(writer, principal.identity, PSK_IDENTITY_LENGTH_BITS)
    }
  }

  private fun serializeSubjectInfo(
    principal: RawPublicKeyIdentity,
    writer: DatagramWriter,
  ) {
    writer.writeByte(ClientAuthenticationType.RPK.code)
    writer.writeBytes(principal.subjectInfo)
  }

  private fun serializeCertChain(
    principal: X509CertPath,
    writer: DatagramWriter,
  ) {
    writer.writeByte(ClientAuthenticationType.CERT.code)
    writer.writeBytes(principal.toByteArray())
  }

  /**
   * Deserializes a principal from its byte array representation.
   * @param reader The reader containing the byte array.
   * @return The principal object or `null` if the reader does not contain a supported principal type.
   * @throws GeneralSecurityException if the reader contains a raw public key principal that could not be recreated.
   * @throws IllegalArgumentException if the reader contains an unsupported ClientAuthenticationType.
   */
  fun deserialize(reader: DatagramReader?): Principal? {
    requireNotNull(reader) { "reader must not be null" }
    val code = reader.readNextByte()
    val type = ClientAuthenticationType.fromCode(code)
    return when (type) {
      ClientAuthenticationType.CERT -> deserializeCertChain(reader)
      ClientAuthenticationType.PSK -> deserializeIdentity(reader)
      ClientAuthenticationType.RPK -> deserializeSubjectInfo(reader)
      else -> null
    }
  }

  private fun deserializeCertChain(reader: DatagramReader): X509CertPath {
    val certificatePath = Asn1DerDecoder.readSequenceEntity(reader)
    return X509CertPath.fromBytes(certificatePath)
  }

  private fun deserializeIdentity(reader: DatagramReader): PreSharedKeyIdentity {
    val scoped: Byte = reader.readNextByte()
    return if (scoped == 1.toByte()) {
      val virtualHost = SerializationUtil.readString(reader, PSK_HOSTNAME_LENGTH_BITS)
      val pskIdentity = SerializationUtil.readString(reader, PSK_IDENTITY_LENGTH_BITS)
      PreSharedKeyIdentity(virtualHost, pskIdentity)
    } else {
      val pskIdentity = SerializationUtil.readString(reader, PSK_IDENTITY_LENGTH_BITS)
      PreSharedKeyIdentity(pskIdentity)
    }
  }

  @Throws(GeneralSecurityException::class)
  private fun deserializeSubjectInfo(reader: DatagramReader): RawPublicKeyIdentity {
    val subjectInfo = Asn1DerDecoder.readSequenceEntity(reader)
    return RawPublicKeyIdentity(subjectInfo)
  }

  enum class ClientAuthenticationType(val code: Byte) {
    ANONYMOUS(0x00.toByte()),
    CERT(0x01.toByte()),
    PSK(0x02.toByte()),
    RPK(0xff.toByte()),
    ;

    companion object {
      fun fromCode(code: Byte): ClientAuthenticationType {
        entries.forEach { type ->
          if (type.code == code) {
            return type
          }
        }
        throw IllegalArgumentException("unknown ClientAuthenticationType: $code")
      }
    }
  }
}
