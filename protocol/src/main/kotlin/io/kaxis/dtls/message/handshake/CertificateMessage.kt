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

import io.kaxis.dtls.CertificateType
import io.kaxis.dtls.HandshakeType
import io.kaxis.dtls.cipher.ThreadLocalCertificateFactory
import io.kaxis.dtls.cipher.ThreadLocalKeyFactory
import io.kaxis.dtls.message.AlertMessage
import io.kaxis.dtls.message.HandshakeMessage
import io.kaxis.exception.HandshakeException
import io.kaxis.util.*
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.GeneralSecurityException
import java.security.PublicKey
import java.security.cert.CertPath
import java.security.cert.Certificate
import java.security.cert.CertificateEncodingException
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec
import javax.security.auth.x500.X500Principal

/**
 * The server MUST send a Certificate message whenever the agreed-upon key
 * exchange method uses certificates for authentication. This message will
 * always immediately follow the [ServerHello] message. For details see [RFC 5246](https://tools.ietf.org/html/rfc5246#section-7.4.2).
 */
class CertificateMessage : HandshakeMessage {
  companion object {
    private const val CERTIFICATE_TYPE_X509 = "X.509"

    private val LOGGER: Logger = LoggerFactory.getLogger(CertificateMessage::class.java)

    /**
     * [RFC 5246](https://tools.ietf.org/html/rfc5246#section-7.4.2): `opaque ASN.1Cert<1..2^24-1>;`
     */
    private val CERTIFICATE_LENGTH_BITS = 24

    /**
     * [RFC 5246](https://tools.ietf.org/html/rfc5246#section-7.4.2): `ASN.1Cert certificate_list<0..2^24-1>;`
     */
    private val CERTIFICATE_LIST_LENGTH_BITS = 24

    /**
     * X509 certificate factory.
     */
    private val CERTIFICATE_FACTORY = ThreadLocalCertificateFactory(CERTIFICATE_TYPE_X509)

    /**
     * Empty certificate chain. Used for empty client certificate messages if no matching certificate is available.
     *
     * Note: [RFC 5246, 7.4.6 Client Certificate](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.6)
     *
     * "If no suitable certificate is available, the client MUST send a
     * certificate message containing no certificates. That is, the
     * certificate_list structure has a length of zero."
     *
     * That complies to the definition of: [RFC 5246, 7.4.2 Server Certificate](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.2).
     *
     * ```
     * struct {
     *  ASN.1Cert certificate_list <0..2^24-1>;
     * }
     * ```
     *
     * (0 as minimum value.) [RFC 7250, 3 Structure of the Raw Public Key Extension](https://www.rfc-editor.org/rfc/rfc7250#section-3) extends that by
     * ```
     * struct {
     *  select(certificate_type) {
     *    // certificate type defined in this document.
     *    case RawPublicKey:
     *      opaque ASN.1_subjectPublicKeyInfo <1..2^24-1>;
     *
     *    // X.509 certificate defined in RFC 5246
     *    case X.509:
     *      ASN.1Cert certificate_list <0..2^24-1>;
     *
     *    // Additional certificate type based on
     *    // "TLS Certificate Types" subregistry
     *  };
     * } Certificate;
     * ```
     *
     * The culprit of this definition is, that the minimum length for a Raw Public key certificate is 1. That creates a
     * contradiction to the client certificate definition in RFC 5246.
     */
    private val EMPTY_CERT_PATH: CertPath

    private val EMPTY_ENCODED_CHAIN: ArrayList<ByteArray>

    init {
      var certPath: CertPath? = null
      try {
        val factory =
          CERTIFICATE_FACTORY.currentWithCause()
            ?: throw GeneralSecurityException("Local CertificateFactory not found!")
        certPath = factory.generateCertPath(listOf())
      } catch (e: GeneralSecurityException) {
        // NOSONAR
      }
      requireNotNull(certPath) { "fail to generate certPath" }
      EMPTY_CERT_PATH = certPath
      EMPTY_ENCODED_CHAIN = arrayListOf()
    }

    /**
     * Creates a certificate message from its binary encoding.
     * @param reader reader for the binary encoding of the message.
     * @param certificateType negotiated type of certificate the certificate message contains.
     * @return The certificate message.
     * @throws HandshakeException if the binary encoding could not be parsed.
     * @throws IllegalArgumentException if the certificate type is not supported.
     */
    @Throws(HandshakeException::class)
    fun fromReader(
      reader: DatagramReader,
      certificateType: CertificateType,
    ): CertificateMessage {
      val certificatesLength = reader.read(CERTIFICATE_LIST_LENGTH_BITS)
      when {
        certificatesLength == 0 -> {
          // anonymous peer
          return CertificateMessage(EMPTY_CERT_PATH)
        }

        CertificateType.RAW_PUBLIC_KEY == certificateType -> {
          LOGGER.debug("Parsing RawPublicKey CERTIFICATE message")
          val rawPublicKey = reader.readBytes(certificatesLength)
          return CertificateMessage(rawPublicKey)
        }

        CertificateType.X_509 == certificateType -> {
          val reader0 = reader.createRangeReader(certificatesLength)
          LOGGER.debug("Parsing X.509 CERTIFICATE message")
          try {
            val factory = CERTIFICATE_FACTORY.currentWithCause()
            val certs = arrayListOf<Certificate>()

            requireNotNull(factory) { "Local CertificateFactory not found!" }

            while (reader0.bytesAvailable()) {
              val certificateLength = reader0.read(CERTIFICATE_LENGTH_BITS)
              certs.add(factory.generateCertificate(reader0.createRangeInputStream(certificateLength)))
            }
            return CertificateMessage(factory.generateCertPath(certs))
          } catch (e: GeneralSecurityException) {
            throw HandshakeException(
              AlertMessage(
                AlertMessage.AlertLevel.FATAL,
                AlertMessage.AlertDescription.BAD_CERTIFICATE,
              ),
              "Cannot parse X.509 certificate chain provided by peer",
              e,
            )
          }
        }

        else -> {
          throw IllegalArgumentException("Certificate type $certificateType not supported!")
        }
      }
    }

    /**
     * Generate _RawPublicKey_ from binary representation.
     * @param rawPublicKeyBytes byte array with binary representation. May be `null` or empty.
     * @return generated public key, or `null`, if the byte array doesn't contain a public key.
     */
    fun generateRawPublicKey(rawPublicKeyBytes: ByteArray?): PublicKey? {
      if (!(rawPublicKeyBytes == null || rawPublicKeyBytes.isEmpty())) {
        try {
          val keyAlgorithm = Asn1DerDecoder.readSubjectPublicKeyAlgorithm(rawPublicKeyBytes)
          if (keyAlgorithm != null) {
            val factory = ThreadLocalKeyFactory.KEY_FACTORIES[keyAlgorithm]
            val fc = factory.current()
            if (fc != null) {
              return fc.generatePublic(X509EncodedKeySpec(rawPublicKeyBytes))
            }
          }
        } catch (e: Throwable) {
          LOGGER.warn("Could not reconstruct the peer's public key", e)
        }
      }
      return null
    }
  }

  /**
   * A chain of certificates asserting the sender's identity. The sender's identity is reflected by the certificate at index 0.
   */
  val certificateChain: CertPath?

  /**
   * The encoded chain of certificates
   */
  val encodedChain: MutableList<ByteArray>?

  /**
   * The SubjectPublicKeyInfo part of the X.509 certificate. Used in constrained environments for smaller message size.
   */
  val rawPublicKeyBytes: ByteArray?

  val publicKey: PublicKey?

  // length is at least 3 bytes containing the message's overall number of bytes
  val length: Int

  /**
   * Creates an empty _CERTIFICATE_ message containing am empty certificate chain.
   */
  constructor() : this(EMPTY_CERT_PATH)

  /**
   * Creates a _CERTIFICATE_ message containing a certificate chain.
   * @param certificateChain the certificate chain with the (first certificate must be the server's)
   * @throws NullPointerException if the certificate chain is `null` (use an array of length zero to create an empty message)
   * @throws IllegalArgumentException if the certificate chain contains any non-X.509 certificates or does not form a valid chain of certification.
   */
  constructor(certificateChain: List<X509Certificate>?) : this(certificateChain, null)

  /**
   * Creates a _CERTIFICATE_ message containing a certificate chain.
   * @param certificateChain the certificate chain with the (first certificate must be the server's)
   * @param certificateAuthorities the certificate authorities to truncate chain. Maybe `null` or empty.
   * @throws NullPointerException if the certificate chain is `null` (use an array of length zero to create an empty message)
   * @throws IllegalArgumentException if the certificate chain contains any non-X.509 certificates or does not form a valid chain of certification.
   */
  constructor(certificateChain: List<X509Certificate>?, certificateAuthorities: List<X500Principal>?) :
    this(CertPathUtil.generateValidatableCertPath(certificateChain, certificateAuthorities)) {
    if (LOGGER.isDebugEnabled) {
      val size = this.certificateChain?.certificates?.size ?: 0
      if (size < (certificateChain?.size ?: 0)) {
        LOGGER.debug(
          "created CERTIFICATE message with truncated certificate chain [length: {}, full-length: {}]",
          size,
          certificateChain?.size ?: 0,
        )
      } else {
        LOGGER.debug("created CERTIFICATE message with certificate chain [length: {}]", size)
      }
    }
  }

  private constructor(peerCertChain: CertPath?) {
    requireNotNull(peerCertChain) { "Certificate chain must not be null!" }
    this.rawPublicKeyBytes = null
    this.certificateChain = peerCertChain

    val certificates = peerCertChain.certificates
    val size = certificates.size
    if (size == 0) {
      this.publicKey = null
      this.encodedChain = EMPTY_ENCODED_CHAIN
      this.length = CERTIFICATE_LENGTH_BITS / Byte.SIZE_BITS
    } else {
      var encodedChain = ArrayList<ByteArray>(size)
      var length = 0
      try {
        certificates.forEach { cert ->
          val encoded = cert.encoded
          encodedChain.add(encoded)

          // the length of the encoded certificate (3 bytes)
          // plus the encoded bytes
          length += (CERTIFICATE_LENGTH_BITS / Byte.SIZE_BITS) + encoded.size
        }
      } catch (e: CertificateEncodingException) {
        encodedChain = EMPTY_ENCODED_CHAIN
        length = 0
        LOGGER.warn("Could not encode certificate chain", e)
      }
      this.publicKey = if (encodedChain.isEmpty()) null else certificates[0].publicKey
      this.encodedChain = encodedChain
      // the certificate chain length uses 3 bytes
      this.length = length + CERTIFICATE_LENGTH_BITS / Byte.SIZE_BITS
    }
  }

  /**
   * Creates a _CERTIFICATE_ message containing a raw public key.
   * @param publicKey the public key, `null` for an empty _CERTIFICATE_ message
   */
  constructor(publicKey: PublicKey?) {
    this.publicKey = publicKey
    if (publicKey == null) {
      this.rawPublicKeyBytes = null
      this.certificateChain = EMPTY_CERT_PATH
      this.encodedChain = EMPTY_ENCODED_CHAIN
      this.length = CERTIFICATE_LENGTH_BITS / Byte.SIZE_BITS
    } else {
      this.certificateChain = null
      this.encodedChain = null
      this.rawPublicKeyBytes = publicKey.encoded
      this.length = (CERTIFICATE_LENGTH_BITS / Byte.SIZE_BITS) + rawPublicKeyBytes.size
    }
  }

  /**
   * Creates a _CERTIFICATE_ message containing a raw public key.
   * @param rawPublicKeyBytes the raw public key (SubjectPublicKeyInfo). `null` or empty array for an empty _CERTIFICATE_ message
   */
  constructor(rawPublicKeyBytes: ByteArray?) : this(generateRawPublicKey(rawPublicKeyBytes))

  override val messageType: HandshakeType
    get() = HandshakeType.CERTIFICATE

  override val messageLength: Int
    get() = length

  /**
   * Is empty certificate message. If a server requests a client certificate, but the client has no proper
   * certificate, the client responds with an empty certificate message.
   * @return `true`, if certificate message contains no certificates, `false`, otherwise.
   */
  val isEmpty: Boolean
    get() = publicKey == null

  override fun fragmentToByteArray(): ByteArray {
    val writer = DatagramWriter(messageLength)

    if (rawPublicKeyBytes == null) {
      writer.write(messageLength - (CERTIFICATE_LENGTH_BITS / Byte.SIZE_BITS), CERTIFICATE_LIST_LENGTH_BITS)
      // the size of the certificate chain
      encodedChain?.forEach { encoded ->
        writer.writeVarBytes(encoded, CERTIFICATE_LENGTH_BITS)
      }
    } else {
      writer.writeVarBytes(rawPublicKeyBytes, CERTIFICATE_LENGTH_BITS)
    }

    return writer.toByteArray()
  }

  override fun toString(indent: Int): String {
    val sb = StringBuilder(super.toString(indent))
    val indentation = Utility.indentation(indent + 1)
    val indentation2 = Utility.indentation(indent + 2)
    if (rawPublicKeyBytes == null && certificateChain != null) {
      val certificates = certificateChain.certificates
      sb.append(indentation).append("Certificate chain: ").append(certificates.size).append(" certificates")
        .append(Utility.LINE_SEPARATOR)
      var index = 0
      certificates.forEach { cert ->
        sb.append(indentation2)
          .append("Certificate Length: ")
          .append(encodedChain?.get(index)?.size ?: 0)
          .append(" bytes").append(Utility.LINE_SEPARATOR)
        val text = Utility.toDisplayString(cert)
        sb.append(indentation2).append("Certificate[").append(index).append(".]:")
        sb.append(text.replace("\n", "\n$indentation2")).append(Utility.LINE_SEPARATOR)
        index++
      }
    } else if (rawPublicKeyBytes != null && certificateChain == null) {
      sb.append(indentation).append("Raw Public Key: ")
      val text =
        if (publicKey != null) {
          val txt = Utility.toDisplayString(publicKey)
          txt.replace("\n", "\n$indentation2")
        } else {
          "<empty>"
        }
      sb.append(text.replace("\n", "\n$indentation2"))
      sb.append(Utility.LINE_SEPARATOR)
    }
    return sb.toString()
  }
}
