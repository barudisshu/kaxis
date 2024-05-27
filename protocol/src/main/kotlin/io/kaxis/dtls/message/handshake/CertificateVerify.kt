/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.message.handshake

import io.kaxis.Bytes
import io.kaxis.JceProvider
import io.kaxis.dtls.HandshakeType
import io.kaxis.dtls.SignatureAndHashAlgorithm
import io.kaxis.dtls.cipher.RandomManager
import io.kaxis.dtls.message.AlertMessage
import io.kaxis.dtls.message.HandshakeMessage
import io.kaxis.exception.HandshakeException
import io.kaxis.util.Asn1DerDecoder
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.GeneralSecurityException
import java.security.PrivateKey
import java.security.PublicKey

/**
 * This message is used to provide explicit verification of a client certificate. This message is only sent following a
 * client certificate that has signing capability (i.e., all certificates except those containing fixed Diffie-Hellman parameters).
 * When sent, it MUST immediately follow the [ClientKeyExchange] message. For further details see [RFC 5246](https://tools.ietf.org/html/rfc5246#section-7.4.8).
 */
class CertificateVerify : HandshakeMessage {
  companion object {
    private val LOGGER: Logger = LoggerFactory.getLogger(CertificateVerify::class.java)

    private const val HASH_ALGORITHM_BITS = 8

    private const val SIGNATURE_ALGORITHM_BITS = 8

    private const val SIGNATURE_LENGTH_BITS = 16

    fun fromReader(reader: DatagramReader): CertificateVerify {
      // according to http://tools.ietf.org/html/rfc5246#section-4.7 the
      // signature algorithm must also be included
      val hashAlgorithm = reader.read(HASH_ALGORITHM_BITS)
      val signatureAlgorithm = reader.read(SIGNATURE_ALGORITHM_BITS)
      val signAndHash = SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm)

      val signature = reader.readVarBytes(SIGNATURE_LENGTH_BITS)

      return CertificateVerify(signAndHash, signature)
    }

    /**
     * Creates the signature and signs it with the client's private key.
     * @param signatureAndHashAlgorithm signature and hash algorithm
     * @param clientPrivateKey the client's private key.
     * @param handshakeMessages the handshake messages used up to now in the handshake.
     * @return the signature
     */
    private fun sign(
      signatureAndHashAlgorithm: SignatureAndHashAlgorithm,
      clientPrivateKey: PrivateKey,
      handshakeMessages: List<HandshakeMessage>,
    ): ByteArray {
      var signatureBytes = Bytes.EMPTY_BYTES

      try {
        val localSignature = signatureAndHashAlgorithm.getThreadLocalSignature()
        val signature =
          localSignature.currentWithCause() ?: throw GeneralSecurityException("Local Signature not found!")
        signature.initSign(clientPrivateKey, RandomManager.currentSecureRandom())
        var index = 0
        handshakeMessages.forEach { message ->
          signature.update(message.toByteArray())
          LOGGER.trace("  [{}] - {}", index, message.messageType)
          ++index
        }
        signatureBytes = signature.sign()
      } catch (e: Throwable) {
        LOGGER.error("Could not create signature.", e)
      }

      return signatureBytes
    }
  }

  /**
   * The digitally signed handshake messages.
   */
  val signatureBytes: ByteArray

  /**
   * The signature and hash algorithm which must be included in the digitally signed struct.
   */
  val signatureAndHashAlgorithm: SignatureAndHashAlgorithm

  /**
   * Called by client to create its CertificateVerify message.
   * @param signatureAndHashAlgorithm the signature and hash algorithm used to create the signature.
   * @param clientPrivateKey the client's private key to sign the signature.
   * @param handshakeMessages the handshake messages which are signed.
   */
  constructor(
    signatureAndHashAlgorithm: SignatureAndHashAlgorithm,
    clientPrivateKey: PrivateKey,
    handshakeMessages: MutableList<HandshakeMessage>,
  ) {
    this.signatureAndHashAlgorithm = signatureAndHashAlgorithm
    this.signatureBytes = sign(signatureAndHashAlgorithm, clientPrivateKey, handshakeMessages)
  }

  /**
   * Called by the server when receiving the client's CertificateVerify message.
   * @param signatureAndHashAlgorithm the signature and hash algorithm used to verify the signature.
   * @param signatureBytes the signature.
   */
  private constructor(signatureAndHashAlgorithm: SignatureAndHashAlgorithm, signatureBytes: ByteArray) {
    this.signatureAndHashAlgorithm = signatureAndHashAlgorithm
    this.signatureBytes = signatureBytes
  }

  /**
   * Tries to verify the client's signature contained in the CertificateVerify message.
   * @param clientPublicKey the client's public key.
   * @param handshakeMessages the handshake messages exchanged so far.
   * @throws HandshakeException if the signature could not be verified.
   */
  @Throws(HandshakeException::class)
  fun verifySignature(
    clientPublicKey: PublicKey,
    handshakeMessages: List<HandshakeMessage>,
  ) {
    try {
      val localSignature = signatureAndHashAlgorithm.getThreadLocalSignature()
      val signature = localSignature.currentWithCause() ?: throw GeneralSecurityException("Local Signature not found!")
      signature.initVerify(clientPublicKey)
      var index = 0
      handshakeMessages.forEach { message ->
        signature.update(message.toByteArray())
        LOGGER.trace("  [{}] - {}", index, message.messageType)
        ++index
      }
      if (signature.verify(signatureBytes)) {
        if (JceProvider.isEcdsaVulnerable() &&
          signatureAndHashAlgorithm.signature == SignatureAndHashAlgorithm.SignatureAlgorithm.ECDSA
        ) {
          Asn1DerDecoder.checkEcDsaSignature(signatureBytes, clientPublicKey)
        }
        return
      }
    } catch (e: GeneralSecurityException) {
      LOGGER.error("Could not verify the client's signature.", e)
    }
    throw HandshakeException(
      AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.DECRYPT_ERROR),
      "The client's CertificateVerify message could not be verified.",
    )
  }

  override val messageType: HandshakeType
    get() = HandshakeType.CERTIFICATE_VERIFY

  override val messageLength: Int
    get() {
      // fixed: signature and hash algorithm (2 bytes) + signature length
      // field (2 bytes), see http://tools.ietf.org/html/rfc5246#section-4.7
      return 4 + signatureBytes.size
    }

  override fun fragmentToByteArray(): ByteArray? {
    val writer = DatagramWriter(signatureBytes.size + 4)

    // according to http://tools.ietf.org/html/rfc5246#section-4.7 the
    // signature algorithm must also be included
    writer.write(signatureAndHashAlgorithm.hashAlgorithmCode, HASH_ALGORITHM_BITS)
    writer.write(signatureAndHashAlgorithm.signatureAlgorithmCode, SIGNATURE_ALGORITHM_BITS)

    writer.writeVarBytes(signatureBytes, SIGNATURE_LENGTH_BITS)

    return writer.toByteArray()
  }

  override fun toString(indent: Int): String {
    return StringBuilder(super.toString(indent)).apply sb@{
      val indentation = Utility.indentation(indent + 1)
      this@sb.append(indentation).append("Signature: ").append(signatureAndHashAlgorithm).append("-")
        .append(Utility.byteArray2HexString(signatureBytes, Utility.NO_SEPARATOR, 16)).append(Utility.LINE_SEPARATOR)
    }.toString()
  }
}
