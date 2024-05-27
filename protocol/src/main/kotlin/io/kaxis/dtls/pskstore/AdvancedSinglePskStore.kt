/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.pskstore

import io.kaxis.dtls.ConnectionId
import io.kaxis.dtls.HandshakeResultHandler
import io.kaxis.dtls.PskPublicInformation
import io.kaxis.dtls.ServerNames
import io.kaxis.result.PskSecretResult
import io.kaxis.util.SecretUtil
import java.net.InetSocketAddress
import javax.crypto.SecretKey
import javax.security.auth.DestroyFailedException
import javax.security.auth.Destroyable

/**
 * [AdvancedPskStore] implementation for clients to connect a single other peer.
 */
class AdvancedSinglePskStore : AdvancedPskStore, Destroyable {
  /**
   * PSK identity.
   */
  val identity: PskPublicInformation

  /**
   * PSK secret key.
   */
  val secret: SecretKey?

  /**
   * Create a simple store with initial credentials.
   *
   * @param identity PSK identity
   * @param key PSK secret key
   */
  constructor(identity: String, key: ByteArray?) : this(PskPublicInformation(identity), key)

  /**
   * Create a simple store with initial credentials.
   *
   * @param identity PSK identity
   * @param key PSK secret key
   */
  constructor(identity: PskPublicInformation, key: ByteArray?) {
    this.identity = identity
    this.secret = SecretUtil.create(key, "PSK")
  }

  /**
   * Create a simple store with initial credentials.
   *
   * @param identity PSK identity
   * @param key PSK secret key
   */
  constructor(identity: String, key: SecretKey?) : this(PskPublicInformation(identity), key)

  /**
   * Create a simple store with initial credentials.
   *
   * @param identity PSK identity
   * @param key PSK secret key
   */
  constructor(identity: PskPublicInformation, key: SecretKey?) {
    this.identity = identity
    this.secret = SecretUtil.create(key)
  }

  override fun hasEcdhePskSupported(): Boolean {
    return true
  }

  override fun requestPskSecretResult(
    cid: ConnectionId,
    serverNames: ServerNames?,
    identity: PskPublicInformation,
    hmacAlgorithm: String,
    otherSecret: SecretKey?,
    seed: ByteArray,
    useExtendedMasterSecret: Boolean,
  ): PskSecretResult {
    var secret: SecretKey? = null
    if (this.identity == identity) {
      secret = SecretUtil.create(this.secret)
    }
    return PskSecretResult(cid, this.identity, secret)
  }

  /**
   * Gets the _identity_ to use for a PSK based handshake with a given peer.
   *
   * A DTLS client uses this method to determine the identity to include in its _CLIENT_KEY_EXCHANGE_
   * message during a PSK based DTLS handshake with the peer. Ignores arguments, though only a single
   * destination peers is supported.
   */
  override fun getIdentity(
    peerAddress: InetSocketAddress?,
    virtualHost: ServerNames?,
  ): PskPublicInformation {
    return identity
  }

  override fun setResultHandler(resultHandler: HandshakeResultHandler) {
    // empty implementation
  }

  @Throws(DestroyFailedException::class)
  override fun destroy() {
    SecretUtil.destroy(secret)
  }

  override fun isDestroyed(): Boolean {
    return SecretUtil.isDestroyed(secret)
  }
}
