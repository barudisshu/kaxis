/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.message.handshake

import io.kaxis.dtls.HandshakeType
import io.kaxis.dtls.cipher.PseudoRandomFunction
import io.kaxis.dtls.message.AlertMessage
import io.kaxis.dtls.message.ChangeCipherSpecMessage
import io.kaxis.dtls.message.HandshakeMessage
import io.kaxis.exception.HandshakeException
import io.kaxis.util.DatagramReader
import io.kaxis.util.Utility
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * A Finished message is always sent immediately after a [ChangeCipherSpecMessage] to verify that the key
 * exchange and authentication processes were successful. It is essential that a [ChangeCipherSpecMessage] be
 * received between the other handshake messages and the Finished message. The Finished message is the first
 * one protected with the just negotiated algorithms, keys, and secrets. The value handshake_messages includes
 * all handshake messages starting at [ClientHello] up to, but not including, this [Finished] message. See [RFC 5246](https://tools.ietf.org/html/rfc5246#section-7.4.9).
 */
class Finished : HandshakeMessage {
  companion object {
    private val LOGGER: Logger = LoggerFactory.getLogger(Finished::class.java)

    fun fromReader(reader: DatagramReader): Finished = Finished(reader)
  }

  val verifyData: ByteArray

  /**
   * Generates the verified data according to [RFC 5246](https://tools.ietf.org/html/rfc5246#section-7.4.9):
   *
   * ```
   *  PRF(master_secret, finished_label, Hash(handshake_messages)).
   * ```
   *
   * @param hmac the mac. e.g. HmacSHA256
   * @param masterSecret the master_secret
   * @param isClient to determine the finished_label
   * @param handshakeHash the hash
   */
  constructor(hmac: Mac, masterSecret: SecretKey, isClient: Boolean, handshakeHash: ByteArray) {
    verifyData = generateVerifyData(hmac, masterSecret, isClient, handshakeHash)
  }

  /**
   * Called when reconstructing byte array.
   * @param reader reader with the raw verify data
   */
  private constructor(reader: DatagramReader) {
    this.verifyData = reader.readBytesLeft()
  }

  /**
   * See [RFC 5246](https://tools.ietf.org/html/rfc5246#section-7.4.9):
   *
   * All of the data from all messages in this handshake (not including any HelloRequest messages) up to,
   * but not including, this message. This is only data visible at the handshake layer and does not include
   * record layer headers.
   * @param hmac the mac. e.g. HmacSHA256
   * @param masterSecret the master secret
   * @param isClient whether the verified data comes from the client or the server.
   * @param handshakeHash the handshake hash
   * @throws HandshakeException if the data cannot be verified.
   */
  @Throws(HandshakeException::class)
  fun verifyData(
    hmac: Mac,
    masterSecret: SecretKey,
    isClient: Boolean,
    handshakeHash: ByteArray,
  ) {
    val myVerifyData = generateVerifyData(hmac, masterSecret, isClient, handshakeHash)
    if (!MessageDigest.isEqual(myVerifyData, verifyData)) {
      val msg = StringBuilder("Verification of FINISHED message failed")
      if (LOGGER.isTraceEnabled) {
        msg.append(Utility.LINE_SEPARATOR).append("Expected: ").append(Utility.byteArray2HexString(myVerifyData))
        msg.append(Utility.LINE_SEPARATOR).append("Received: ").append(Utility.byteArray2HexString(verifyData))
      }
      LOGGER.debug(msg.toString())
      throw HandshakeException(
        AlertMessage(AlertMessage.AlertLevel.FATAL, AlertMessage.AlertDescription.DECRYPT_ERROR),
        "Verification of FINISHED message failed",
      )
    }
  }

  fun generateVerifyData(
    hmac: Mac,
    masterSecret: SecretKey,
    isClient: Boolean,
    handshakeHash: ByteArray,
  ): ByteArray {
    // See http://tools.ietf.org/html/rfc5246#section-7.4.9:
    // verify_data = PRF(master_secret, finished_label,
    // Hash(handshake_messages)) [0..verify_data_length-1]
    return if (isClient) {
      PseudoRandomFunction.doPRF(hmac, masterSecret, PseudoRandomFunction.Label.CLIENT_FINISHED_LABEL, handshakeHash)
    } else {
      PseudoRandomFunction.doPRF(hmac, masterSecret, PseudoRandomFunction.Label.SERVER_FINISHED_LABEL, handshakeHash)
    }
  }

  override val messageType: HandshakeType
    get() = HandshakeType.FINISHED

  override val messageLength: Int
    get() = verifyData.size

  override fun fragmentToByteArray(): ByteArray {
    return verifyData
  }

  override fun toString(indent: Int): String {
    return StringBuilder(super.toString(indent)).apply sb@{
      val indentation = Utility.indentation(indent + 1)
      this@sb.append(indentation).append("Verify Data: ").append(Utility.byteArray2HexString(verifyData))
        .append(Utility.LINE_SEPARATOR)
    }.toString()
  }
}
