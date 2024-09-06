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

import io.kaxis.JceProvider
import io.kaxis.dtls.Random
import io.kaxis.dtls.SignatureAndHashAlgorithm
import io.kaxis.dtls.cipher.RandomManager
import io.kaxis.dtls.cipher.XECDHECryptography
import io.kaxis.dtls.message.AlertMessage
import io.kaxis.exception.HandshakeException
import io.kaxis.util.Asn1DerDecoder
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.*

class EcdhSignedServerKeyExchange : ECDHServerKeyExchange {
  companion object {
    private val LOGGER: Logger = LoggerFactory.getLogger(EcdhSignedServerKeyExchange::class.java)

    private const val HASH_ALGORITHM_BITS = 8
    private const val SIGNATURE_ALGORITHM_BITS = 8
    private const val SIGNATURE_LENGTH_BITS = 16

    @Throws(HandshakeException::class)
    fun fromReader(reader: DatagramReader): EcdhSignedServerKeyExchange {
      val ecdhData = readNamedCurve(reader)

      var signAndhash: SignatureAndHashAlgorithm? = null
      var signatureEncoded: ByteArray? = null

      if (reader.bytesAvailable()) {
        val hashAlgorithm = reader.read(HASH_ALGORITHM_BITS)
        val signatureAlgorithm = reader.read(SIGNATURE_ALGORITHM_BITS)
        signAndhash = SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm)
        signatureEncoded = reader.readVarBytes(SIGNATURE_LENGTH_BITS)
      }
      return EcdhSignedServerKeyExchange(signAndhash, ecdhData.supportedGroup, ecdhData.encodedPoint, signatureEncoded)
    }
  }

  val signatureEncoded: ByteArray?

  /**
   * The signature and hash algorithm which must be included into the digitally-signed struct.
   */
  val signatureAndHashAlgorithm: SignatureAndHashAlgorithm?

  /**
   * Called by server with generated ephemeral keys and generates signature.
   * @param signatureAndHashAlgorithm the algorithm to use
   * @param ecdhe the ECDHE hlper class. Contains generated ephemeral keys.
   * @param serverPrivateKey the server's private key
   * @param clientRandom the client's random (used for signature)
   * @param serverRandom the server's random (used for signature)
   * @throws HandshakeException if generating the signature providing prove of possession of the private key fails, e.g.
   * due to an unsupported signature or hash algorithm or an invalid key
   */
  constructor(
    signatureAndHashAlgorithm: SignatureAndHashAlgorithm?,
    ecdhe: XECDHECryptography,
    serverPrivateKey: PrivateKey?,
    clientRandom: Random,
    serverRandom: Random,
  ) : super(ecdhe.supportedGroup, ecdhe.encodedPoint) {
    requireNotNull(signatureAndHashAlgorithm) { "signature and hash algorithm cannot be null" }
    this.signatureAndHashAlgorithm = signatureAndHashAlgorithm

    // make signature
    // See http://tools.ietf.org/html/rfc4492#section-2.2
    // These parameters MUST be signed using the private key
    // corresponding to the public key in the server's Certificate.
    val localSignature = signatureAndHashAlgorithm.getThreadLocalSignature()
    try {
      val signature = localSignature.currentWithCause() ?: throw GeneralSecurityException("Local signature not found1")
      signature.initSign(serverPrivateKey, RandomManager.currentSecureRandom())
      updateSignature(signature, clientRandom, serverRandom)
      signatureEncoded = signature.sign()
    } catch (e: GeneralSecurityException) {
      throw HandshakeException(
        AlertMessage(
          AlertMessage.AlertLevel.FATAL,
          AlertMessage.AlertDescription.ILLEGAL_PARAMETER,
        ),
        "Server failed to sign key exchange: %s".format(e.message),
      )
    }
  }

  /**
   * Called when reconstructing from the byte array.
   * @param signatureAndHashAlgorithm the algorithm to use
   * @param supportedGroup the supported group (curve)
   * @param encodedPoint the encoded point of the other peer (public key)
   * @param signatureEncoded the signature (encoded)
   * @throws NullPointerException if only one of the parameters signatureAndHashAlgorithm and signatureEncoded is `null`, or any of the other parameters.
   */
  private constructor(
    signatureAndHashAlgorithm: SignatureAndHashAlgorithm?,
    supportedGroup: XECDHECryptography.SupportedGroup?,
    encodedPoint: ByteArray?,
    signatureEncoded: ByteArray?,
  ) : super(supportedGroup, encodedPoint) {
    if (signatureAndHashAlgorithm == null && signatureEncoded != null) {
      throw NullPointerException("signature and hash algorithm cannot be null")
    }
    if (signatureAndHashAlgorithm != null && signatureEncoded == null) {
      throw NullPointerException("signature cannot be null")
    }
    this.signatureAndHashAlgorithm = signatureAndHashAlgorithm
    this.signatureEncoded = signatureEncoded
  }

  override val messageLength: Int
    get() {
      // the signature length field uses 2 bytes, if a signature available
      val signatureLength = if (signatureEncoded == null) 0 else 2 + 2 + signatureEncoded.size
      return namedCurveLength + signatureLength
    }

  override fun fragmentToByteArray(): ByteArray {
    val writer = DatagramWriter()
    writeNamedCurve(writer)

    // signature
    if (signatureEncoded != null && signatureAndHashAlgorithm != null) {
      // according to
      // https://datatracker.ietf.org/doc/html/rfc5246#appendix-A.7 the
      // signature algorithm must also be included
      writer.write(signatureAndHashAlgorithm.hash!!.code, HASH_ALGORITHM_BITS)
      writer.write(signatureAndHashAlgorithm.signature!!.code, SIGNATURE_ALGORITHM_BITS)

      writer.writeVarBytes(signatureEncoded, SIGNATURE_LENGTH_BITS)
    }
    return writer.toByteArray()
  }

  /**
   * Called by the client after receiving the server's [ServerKeyExchange] message. Verifies the contained signature.
   * @param serverPublicKey the server's public key.
   * @param clientRandom the client's random (used in signature).
   * @param serverRandom the server's random (used in signature).
   * @throws HandshakeException if the signature could not be verified.
   */
  @Throws(HandshakeException::class)
  fun verifySignature(
    serverPublicKey: PublicKey,
    clientRandom: Random,
    serverRandom: Random,
  ) {
    if (signatureEncoded == null) {
      throw HandshakeException(
        AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.DECRYPT_ERROR),
        "The server's ECDHE key exchange message has no signature.",
      )
    }
    if (signatureAndHashAlgorithm == null) {
      throw HandshakeException(
        AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.DECRYPT_ERROR),
        "The server's ECDHE key exchange message has not hash algorithm",
      )
    }
    try {
      val localSignature = signatureAndHashAlgorithm.getThreadLocalSignature()
      val signature = localSignature.currentWithCause() ?: throw GeneralSecurityException("Local signature not found!")
      signature.initVerify(serverPublicKey)

      updateSignature(signature, clientRandom, serverRandom)

      if (signature.verify(signatureEncoded)) {
        if (JceProvider.isEcdsaVulnerable() &&
          signatureAndHashAlgorithm.signature == SignatureAndHashAlgorithm.SignatureAlgorithm.ECDSA
        ) {
          Asn1DerDecoder.checkEcDsaSignature(signatureEncoded, serverPublicKey)
        }
        return
      }
    } catch (e: GeneralSecurityException) {
      LOGGER.error("Could not verify the server's signature.", e)
    }
    throw HandshakeException(
      AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.DECRYPT_ERROR),
      "The server's ECDHE key exchange message's signature could not be verified.",
    )
  }

  /**
   * Update the signature:
   *
   * ```
   * SHA(ClientHello.random + ServerHello.random + ServerKeyExchange.params)
   * ```
   *
   * See [RFC 492, Section 5.4. Server Key Exchange](https://tools.ietf.org/html/rfc4492#section-5.4) for further details on the signature format.
   * @param signature the signature
   * @param clientRandom the client random
   * @param serverRandom the server random
   * @throws SignatureException the signature exception
   */
  @Throws(SignatureException::class)
  private fun updateSignature(
    signature: Signature,
    clientRandom: Random,
    serverRandom: Random,
  ) {
    signature.update(clientRandom.byteArray)
    signature.update(serverRandom.byteArray)
    updateSignatureForNamedCurve(signature)
  }

  override fun toString(indent: Int): String {
    var text = super.toString(indent)
    if (signatureEncoded != null) {
      val sb = StringBuilder(text)
      val indentation = Utility.indentation(indent + 1)
      sb.append(indentation).append("Signature: ")
      sb.append(signatureAndHashAlgorithm).append("-")
      sb.append(Utility.byteArray2HexString(signatureEncoded, Utility.NO_SEPARATOR, 16))
      sb.append(Utility.LINE_SEPARATOR)
      text = sb.toString()
    }
    return text
  }
}
