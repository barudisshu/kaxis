/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.util

import io.kaxis.Bytes
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.MessageDigest
import java.security.spec.KeySpec
import java.util.*
import javax.crypto.SecretKey
import javax.security.auth.DestroyFailedException
import javax.security.auth.Destroyable

/**
 * Utility to use [Destroyable] [SecretKey] for java before 1.8.
 */
object SecretUtil {
  private val LOGGER: Logger = LoggerFactory.getLogger(SecretUtil::class.java)

  fun destroy(destroyable: Destroyable?) {
    if (destroyable != null) {
      try {
        destroyable.destroy()
      } catch (e: DestroyFailedException) {
        // Using SecretIvParameterSpec or SecretKey created by this class
        // should never throw it. Using other Destroyable implementations
        // may throw it.
        LOGGER.warn("Destroy on {} failed!", destroyable.javaClass, e)
      }
    }
  }

  /**
   * Check if a secret key has already been destroyed.
   * @param key secret key to check (may be `null`).
   * @return `true` if the key either is `null` or has been destroyed.
   */
  fun isDestroyed(key: SecretKey?): Boolean {
    return key?.isDestroyed ?: false
  }

  /**
   * Checks if a given destroyable has already been destroyed.
   * @param destroyable the destroyable to check (may be `null`).
   * @return `true` if the given object either is `null` or has been destroyed.
   */
  fun isDestroyed(destroyable: Destroyable?): Boolean {
    return destroyable == null || destroyable.isDestroyed
  }

  fun create(
    secret: ByteArray?,
    algorithm: String,
  ): SecretKey = DestroyableSecretKeySpec(secret, algorithm)

  fun create(
    secret: ByteArray?,
    offset: Int,
    length: Int,
    algorithm: String,
  ) = DestroyableSecretKeySpec(secret, offset, length, algorithm)

  fun create(key: SecretKey?): SecretKey? {
    var result: SecretKey? = null
    if (key != null) {
      val secret = key.encoded
      result = DestroyableSecretKeySpec(secret, key.algorithm)
      Bytes.clear(secret)
    }
    return result
  }

  /**
   * Creates copy of a secret init vector.
   * @param iv the init vector to copy(may be `null`).
   * @return the newly created IV, or `null` if the provided IV was `null`.
   */
  fun createIv(iv: SecretIvParameterSpec?): SecretIvParameterSpec? {
    return iv?.let { SecretIvParameterSpec(it) }
  }

  /**
   * Create secret iv parameter (with destroyable implementation).
   * @param iv as byte array
   * @param offset offset of iv within the provided byte array
   * @param length length of iv
   * @return the secret iv
   * @throws NullPointerException if iv is `null`
   * @throws IllegalArgumentException if iv is empty, or length is negative or offset and length doesn't fit into iv.
   */
  fun createIv(
    iv: ByteArray?,
    offset: Int,
    length: Int,
  ): SecretIvParameterSpec {
    return SecretIvParameterSpec(iv, offset, length)
  }

  /**
   * Create secret iv parameter (with destroyable implementation).
   * @param iv as byte array
   * @return the secret iv
   * @throws NullPointerException if iv is `null`
   */
  fun createIv(iv: ByteArray?): SecretIvParameterSpec {
    return SecretIvParameterSpec(iv)
  }

  /**
   * Indicates whether some secret keys are "equal to" each other.
   * @param key1 first key to check
   * @param key2 second key to check
   * @return `true`, if the keys are equal, `false`, otherwise.
   *
   */
  fun equals(
    key1: SecretKey?,
    key2: SecretKey?,
  ): Boolean {
    if (key1 == key2) {
      return true
    } else if (key1 == null || key2 == null) {
      return false
    }
    if (key1.algorithm != key2.algorithm) {
      return false
    }
    val secret1 = key1.encoded
    val secret2 = key2.encoded
    val ok = secret1.contentEquals(secret2)
    Bytes.clear(secret1)
    Bytes.clear(secret2)
    return ok
  }

  class DestroyableSecretKeySpec : KeySpec, SecretKey, Destroyable {
    private val hashCode: Int

    /**
     * The secret key.
     */
    val key: ByteArray

    /**
     * The name of the algorithm associated with this key.
     */
    private val algorithm: String

    /**
     * Indicates, that this instance has been [destroy]ed.
     */
    @Volatile
    var destroyed: Boolean = false

    constructor(key: ByteArray?, algorithm: String) : this(key, 0, key?.size ?: 0, algorithm)

    constructor(key: ByteArray?, offset: Int, len: Int, algorithm: String?) {
      requireNotNull(key) { "Key missing" }
      requireNotNull(algorithm) { "Algorithm missing" }
      require(key.isNotEmpty()) { "Empty key" }
      require(key.size - offset >= len) { "Invalid offset/length combination" }
      if (len < 0) throw ArrayIndexOutOfBoundsException("len is negative")
      this.key = Arrays.copyOfRange(key, offset, offset + len)
      this.algorithm = algorithm
      this.hashCode = calcHashCode()
    }

    private fun calcHashCode(): Int = hashCode

    override fun getAlgorithm(): String {
      return algorithm
    }

    override fun getFormat(): String {
      return "RAW"
    }

    override fun getEncoded(): ByteArray {
      check(!destroyed) { "secret destroyed!" }
      return key.clone()
    }

    override fun hashCode(): Int {
      return hashCode
    }

    override fun equals(other: Any?): Boolean {
      if (this === other) {
        return true
      } else if (other !is SecretKey) {
        return false
      }
      if (!algorithm.equals(other.algorithm, true)) {
        return false
      }
      check(!destroyed) { "secret destroyed!" }
      val otherKey = other.encoded
      val result = MessageDigest.isEqual(key, otherKey)
      Bytes.clear(otherKey)
      return result
    }

    /**
     * Destroy key material! [equals] and [hashCode] must not be used after the key is destroyed!
     */
    override fun destroy() {
      Bytes.clear(key)
      destroyed = true
    }

    override fun isDestroyed(): Boolean {
      return destroyed
    }
  }
}
