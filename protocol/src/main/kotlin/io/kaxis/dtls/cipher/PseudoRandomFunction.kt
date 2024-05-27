/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.cipher

import io.kaxis.Bytes
import io.kaxis.util.DatagramWriter
import io.kaxis.util.SecretUtil
import java.nio.charset.StandardCharsets
import java.security.InvalidKeyException
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.ShortBufferException

/**
 * The Pseudo Random Function as defined in TLS 1.2.
 * @see [RFC 5246](https://tools.ietf.org/html/rfc5246#section-5)
 */
object PseudoRandomFunction {
  enum class Label(val value: String, val length: Int) {
    // The master secret is always 48 bytes long, see
    // http://tools.ietf.org/html/rfc5246#section-8.1
    MASTER_SECRET_LABEL("master secret", 48),

    // The most key material required is 128 bytes, see
    // http://tools.ietf.org/html/rfc5246#section-6.3
    // (some cipher suites, not mentioned in rfc5246 requires more!)
    KEY_EXPANSION_LABEL("key expansion", 128),

    // The verify data is always 12 bytes long, see
    // http://tools.ietf.org/html/rfc5246#section-7.4.9
    CLIENT_FINISHED_LABEL("client finished", 12),

    // The verify data is always 12 bytes long, see
    // http://tools.ietf.org/html/rfc5246#section-7.4.9
    SERVER_FINISHED_LABEL("server finished", 12),

    // The extended master secret is always 48 bytes long, see
    // http://tools.ietf.org/html/rfc7621#section-4
    EXTENDED_MASTER_SECRET_LABEL("extended master secret", 48),
    ;

    val bytesValue: ByteArray

    init {
      bytesValue = value.toByteArray(StandardCharsets.UTF_8)
    }
  }

  private val EXPORTER = "EXPORTER".toByteArray()
  private val EXPERIMENTAL = "EXPERIMENTAL".toByteArray()

  /**
   * Check, if array starts with other array.
   * @param value value to check
   * @param start header to check
   * @return `true`, if value starts with header, `false` otherwise.
   */
  private fun startsWith(
    value: ByteArray,
    start: ByteArray,
  ): Boolean {
    if (value.size < start.size) return false
    for (index in start.indices) {
      if (value[index] != start[index]) {
        return false
      }
    }
    return true
  }

  /**
   * Check, if the provided label is supported for key material export.
   * @param label label to check
   * @return `true`, if allowed, `false`, if not.
   */
  fun isExportLabel(label: ByteArray): Boolean {
    if (startsWith(label, EXPORTER)) return true
    if (startsWith(label, EXPERIMENTAL)) return true
    return false
  }

  /**
   * Does the pseudo random function as defined in [RFC 5246](https://tools.ietf.org/html/rfc5246#section-5).
   * @param hmac MAC algorithm. e.g. HmacSHA256
   * @param label the label to use for creating the original data.
   * @param seed the seed to use for creating the original data
   * @param length the length of data to create
   * @return the expanded data
   */
  fun doPRF(
    hmac: Mac,
    secret: SecretKey,
    label: ByteArray,
    seed: ByteArray,
    length: Int,
  ): ByteArray {
    try {
      hmac.init(secret)
      val prf = doExpansion(hmac, label, seed, length)
      hmac.reset()
      return prf
    } catch (e: InvalidKeyException) {
      // according to http://www.ietf.org/rfc/rfc2104 (HMAC) section 3
      // keys can be of arbitrary length
      throw IllegalArgumentException("Cannot run Pseudo Random Function with invalid key", e)
    }
  }

  /**
   * Calculate the pseudo random function for exporter as defined in [RFC 5246](https://tools.ietf.org/html/rfc5246#section-5).
   * @param hmac MAC algorithm. e.g. HmacSHA256
   * @param label the label to use for creating the original data.
   * @param seed the seed to use for creating the original data
   * @param length the length of data to create
   * @return the expanded data
   * @throws IllegalArgumentException if label is not allowed for exporter.
   * @see [RFC 5705](https://tools.ietf.org/html/rfc5705)
   */
  fun doExporterPRF(
    hmac: Mac,
    secret: SecretKey,
    label: ByteArray,
    seed: ByteArray,
    length: Int,
  ): ByteArray {
    require(isExportLabel(label)) { "label must be valid for export!" }
    return doPRF(hmac, secret, label, seed, length)
  }

  /**
   * Does the pseudo random function as defined in [RFC 5246](https://tools.ietf.org/html/rfc5246#section-5).
   * @param hmac MAC algorithm. e.g. HmacSHA256
   * @param label the label to use for creating the original data.
   * @param seed the seed to use for creating the original data
   * @param length the length of data to create
   * @return the expanded data
   */
  fun doPRF(
    hmac: Mac,
    secret: SecretKey,
    label: Label,
    seed: ByteArray,
  ): ByteArray {
    return doPRF(hmac, secret, label.bytesValue, seed, label.length)
  }

  /**
   * Does the pseudo random function as defined in [RFC 5246](https://tools.ietf.org/html/rfc5246#section-5).
   * @param hmac MAC algorithm. e.g. HmacSHA256
   * @param label the label to use for creating the original data.
   * @param seed the seed to use for creating the original data
   * @param length the length of data to create
   * @return the expanded data
   */
  fun doPRF(
    hmac: Mac,
    secret: SecretKey,
    label: Label,
    seed: ByteArray,
    length: Int,
  ): ByteArray {
    return doPRF(hmac, secret, label.bytesValue, seed, length)
  }

  /**
   * Performs the secret expansion as described in [RFC 5246](https://tools.ietf.org/html/rfc5246#section-5).
   *
   * ```
   * RFC 5246, chapter 5, page 15
   * P_hash(secret, seed) =
   *    HMAC_hash(secret, A(1) + seed +
   *    HMAC_hash(secret, A(2) + seed +
   *    HMAC_hash(secret, A(3) + seed + ...
   * where + indicates concatenation.
   *
   * A() is defined as:
   *    A(0) = seed,
   *    A(1) = HMAC_hash(secret, A(i-1))
   * ```
   *
   * @param hmac MAC algorithm. e.g. HmacSHA256
   * @param label the label to use for creating the original data.
   * @param seed the seed to use for creating the original data
   * @param length the length of data to create
   * @return the expanded data
   */
  fun doExpansion(
    hmac: Mac,
    label: ByteArray,
    seed: ByteArray,
    length: Int,
  ): ByteArray {
    var offset = 0
    val macLength = hmac.macLength
    val aAndSeed = ByteArray(macLength + label.size + seed.size)
    val expansion = ByteArray(length)

    try {
      // copy appended seed to buffer end
      System.arraycopy(label, 0, aAndSeed, macLength, label.size)
      System.arraycopy(seed, 0, aAndSeed, macLength + label.size, seed.size)
      // calculate A(n) from A(0)
      hmac.update(label)
      hmac.update(seed)
      while (true) {
        // write result to "A(n) + seed"
        hmac.doFinal(aAndSeed, 0)
        // calculate HMAC_hash from "A(n) + seed"
        hmac.update(aAndSeed)
        val nextOffset = offset + macLength
        if (nextOffset > length) {
          // too large for expansion!
          // write HMAC_hash result temporary to "A(n) + seed"
          hmac.doFinal(aAndSeed, 0)
          // write head of result from temporary "A(n) + seed" to expansion
          System.arraycopy(aAndSeed, 0, expansion, offset, length - offset)
          break
        } else {
          // write HMAC_hash result to expansion
          hmac.doFinal(expansion, offset)
          if (nextOffset == length) break
        }
        offset = nextOffset
        // calculate A(n+1) from "A(n) + seed" head ("A(n)")
        hmac.update(aAndSeed, 0, macLength)
      }
    } catch (e: ShortBufferException) {
      // NOSONAR
    }
    Bytes.clear(aAndSeed)
    return expansion
  }

  /**
   * Generate (extended) master secret.
   * @param hmac MAC algorithm. e.g. HmacSHA256
   * @param premasterSecret the secret to use for the secure hash function
   * @param seed the seed to use for creating the master secret
   * @param extended `true`, use [PseudoRandomFunction.Label.EXTENDED_MASTER_SECRET_LABEL], `false`, use [PseudoRandomFunction.Label.MASTER_SECRET_LABEL]
   * @return the (extended) master secret
   */
  fun generateMasterSecret(
    hmac: Mac,
    premasterSecret: SecretKey,
    seed: ByteArray,
    extended: Boolean,
  ): SecretKey {
    val secret =
      doPRF(
        hmac,
        premasterSecret,
        if (extended) Label.EXTENDED_MASTER_SECRET_LABEL else Label.MASTER_SECRET_LABEL,
        seed,
      )
    val masterSecret = SecretUtil.create(secret, "MAC")
    Bytes.clear(secret)
    return masterSecret
  }

  /**
   * The premaster secret is formed as follows: if the PSK is N octets long, concatenate a uint16 with the value
   * N, N zero octets, a second uint16 with the value N, and the PSK itself.
   *
   * #### What we are building is the following with length fields in between:
   * ```
   * struct {
   *    opaque other_secret<0..2^16-1>;
   *    opaque psk<0..2^16-1>;
   * };
   * ```
   * See [RFC 4279](https://tools.ietf.org/html/rfc4279#section-2)
   *
   * @param otherSecret either is zeroes (plain PSK case) or comes from the EC Diffie-Hellman exchange (ECDHE_PSK).
   * @param pskSecret PSK secret.
   * @return byte array with generated premaster secret.
   *
   */
  fun generatePremasterSecretFromPSK(
    otherSecret: SecretKey?,
    pskSecret: SecretKey,
  ): SecretKey {
    val pskBytes = pskSecret.encoded
    val pskLength = pskBytes.size
    val otherBytes = if (otherSecret != null) otherSecret.encoded else ByteArray(pskLength)
    val writer = DatagramWriter(otherBytes.size + pskLength + 4, true)
    writer.writeVarBytes(otherBytes, 16)
    writer.writeVarBytes(pskBytes, 16)
    val secret = writer.toByteArray()
    writer.close()
    val premaster = SecretUtil.create(secret, "MAC")
    Bytes.clear(pskBytes)
    Bytes.clear(otherBytes)
    Bytes.clear(secret)
    return premaster
  }
}
