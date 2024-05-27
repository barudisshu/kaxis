/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls

import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.dtls.message.handshake.ClientHello
import io.kaxis.util.ClockUtil
import io.kaxis.util.SecretUtil
import java.net.InetSocketAddress
import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantReadWriteLock
import javax.crypto.SecretKey

/**
 * Generates a cookie in such a way that they can be verified without retaining any per-client state on the server.
 * ```
 *  Cookie = HMAC(Secret, Client - IP, Client - Parameters)
 * ```
 * as suggested [RFC 6347, section 4.2.1](https://tools.ietf.org/html/rfc6347#section-4.2.1).
 */
class CookieGenerator {
  companion object {
    /**
     * Cookie's key lifetime in nanos. Considering the current and the past cookie enables the client to execute
     * handshakes also when the cookie key has changed. That usually requires a new challenge with a
     * _HELLO_VERIFY_REQUEST_, but supporting also the past cookie eliminates the need of that extra
     * exchange. The lifetime of a _CLIENT_HELLO_ therefore spans also twice this value.
     */
    val COOKIE_LIFETIME_NANOS: Long = TimeUnit.SECONDS.toNanos(60)
  }

  /**
   * Nanos of next key generation.
   */
  private var nextKeyGenerationNanos: Long = 0

  /**
   * Current secret key.
   */
  private var currentSecretKey: SecretKey? = null

  /**
   * Past secret key.
   */
  private var pastSecretKey: SecretKey? = null

  /**
   * Lock to protect access to [currentSecretKey], [pastSecretKey], [randomBytes] and [randomGenerator].
   */
  private val lock = ReentrantReadWriteLock()

  // attributes used for random byte generation
  private val randomGenerator = SecureRandom()
  private val randomBytes = ByteArray(32)

  /**
   * Return the secret key for cookie generation. Secret key is refreshed every [COOKIE_LIFETIME_NANOS] nanoseconds.
   * @return secret key
   */
  private fun getSecretKey(): SecretKey {
    lock.readLock().lock()
    val now = ClockUtil.nanoRealtime()
    try {
      // check, if a secret key is already created and not expired
      if (currentSecretKey != null && (now - nextKeyGenerationNanos) < 0) {
        return currentSecretKey!!
      }
    } finally {
      lock.readLock().unlock()
    }

    // if key expired or secret key not initialized;
    lock.writeLock().lock()
    try {
      // re-check, if a secret key is already created and not expired
      if (currentSecretKey != null && (now - nextKeyGenerationNanos) < 0) {
        return currentSecretKey!!
      }
      randomGenerator.nextBytes(randomBytes)
      nextKeyGenerationNanos = now + COOKIE_LIFETIME_NANOS
      // shift secret keys
      pastSecretKey = currentSecretKey
      currentSecretKey = SecretUtil.create(randomBytes, "MAC")
      return currentSecretKey!!
    } finally {
      lock.writeLock().unlock()
    }
  }

  /**
   * Return the secret key of the past period.
   * @return past secret key
   */
  private fun getPastSecretKey(): SecretKey? {
    lock.readLock().lock()
    try {
      return pastSecretKey
    } finally {
      lock.readLock().unlock()
    }
  }

  /**
   * Generates a cookie in such a way that they can be verified without retaining any per-client state on the server.
   * ```
   *  Cookie = HMAC(Secret, Client - IP, Client - Parameters)
   * ```
   * The secret is a serer-side secret which should be changed frequently. Keeping the secret for a long time, a new
   * attack is possible. An adversary can collect several cookies from different IP addresses and reuse them later.
   * Changing the secret will invalidate all previous cookies. See [RFC 6347, section 4.2.1](https://tools.ietf.org/html/rfc6347#section-4.2.1)
   *
   * @param peer address of the peer
   * @param clientHello received client hello to generate a cookie for
   * @param secretKey to generate a cookie for
   * @return the cookie generated from the client's parameters
   * @throws GeneralSecurityException if the cookie cannot be computed
   */
  @Throws(GeneralSecurityException::class)
  private fun generateCookie(
    peer: InetSocketAddress,
    clientHello: ClientHello,
    secretKey: SecretKey,
  ): ByteArray {
    val hmac =
      CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256.threadLocalMac
        ?: throw GeneralSecurityException("Local HMAC not found!")
    hmac.init(secretKey)
    // Client-IP
    hmac.update(peer.address.address)
    val port = peer.port
    hmac.update((port ushr 8).toByte())
    hmac.update(port.toByte())
    // Client-Parameters
    clientHello.updateForCookie(hmac)
    return hmac.doFinal()
  }

  /**
   * Generates a cookie in such a way that they can be verified without retaining any per-client state on
   * the server.
   * ```
   *  Cookie = HMAC(Secret, Client - IP, Client - Parameters)
   * ```
   * As suggested [RFC 6347, section 4.2.1](https://tools.ietf.org/html/rfc6347#section-4.2.1).
   * @param peer address of the peer
   * @param clientHello received client hello to generate a cookie for
   * @return the cookie generated from the client's parameters
   * @throws GeneralSecurityException if the cookie cannot be computed
   */
  @Throws(GeneralSecurityException::class)
  fun generateCookie(
    peer: InetSocketAddress,
    clientHello: ClientHello,
  ): ByteArray {
    return generateCookie(peer, clientHello, getSecretKey())
  }

  /**
   * Generates the cookie using the secret key of the past period.
   * @param peer address of the peer
   * @param clientHello received client hello to generate a cookie for
   * @return the cookie generated for the client's parameters. `null`, if no secret key of the past period is availabe.
   * @throws GeneralSecurityException if the cookie cannot be computed
   */
  @Throws(GeneralSecurityException::class)
  fun generatePastCookie(
    peer: InetSocketAddress,
    clientHello: ClientHello,
  ): ByteArray? {
    val secretKey = getPastSecretKey()
    return if (secretKey != null) {
      generateCookie(peer, clientHello, secretKey)
    } else {
      null
    }
  }
}
