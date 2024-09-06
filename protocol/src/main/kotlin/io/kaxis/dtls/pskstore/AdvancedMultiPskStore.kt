/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.pskstore

import io.kaxis.Bytes
import io.kaxis.dtls.*
import io.kaxis.result.PskSecretResult
import io.kaxis.util.SecretUtil
import java.net.InetSocketAddress
import java.util.concurrent.locks.ReentrantReadWriteLock
import javax.crypto.SecretKey
import javax.security.auth.Destroyable

/**
 * [AdvancedPskStore] implementation supporting multiple peers.
 *
 * If you don't need to initiate handshake/connection, you could just add
 * identity/key with [setKey(String, ByteArray)]
 * or [setKey(PskPublicInformation, ByteArray)]. If you need to initiate
 * connection, you should add known peers with
 * [addKnownPeer(InetSocketAddress, String, ByteArray)] or
 * [addKnownPeer(InetSocketAddress, PskPublicInformation, ByteArray)].
 *
 * If non-compliant encoded identities are used, please provide
 * [PskPublicInformation#constructor(String, ByteArray)] identities
 * with the non-compliant encoded bytes and the intended string.
 *
 * To be used only for testing and evaluation. You are supported to store your
 * key in a secure way: keeping them in-memory is not a good idea.
 */
class AdvancedMultiPskStore : AdvancedPskStore, Destroyable {
  companion object {
    private val GLOBAL_SCOPE = ServerName.from(ServerName.NameType.UNDEFINED, Bytes.EMPTY_BYTES)

    private class PskCredentials : Destroyable {
      val identity: PskPublicInformation
      val key: SecretKey?
        get() = SecretUtil.create(field)

      constructor(identity: PskPublicInformation, key: ByteArray?) {
        this.identity = identity
        this.key = SecretUtil.create(key, PskSecretResult.ALGORITHM_PSK)
      }

      override fun destroy() {
        SecretUtil.destroy(key)
      }

      override fun isDestroyed(): Boolean {
        return SecretUtil.isDestroyed(key)
      }
    }

    private val scopedKeys: MutableMap<ServerName, MutableMap<PskPublicInformation, PskCredentials>> =
      mutableMapOf()
    private val scopedIdentities: MutableMap<InetSocketAddress, MutableMap<ServerName, PskPublicInformation>> =
      mutableMapOf()

    @Volatile
    private var destroyed: Boolean = false

    private fun getPskCredentials(
      identity: PskPublicInformation,
      keyMap: Map<PskPublicInformation, PskCredentials>?,
    ): PskCredentials? {
      if (keyMap != null) {
        return keyMap[identity]
      }
      return null
    }

    private fun getIdentityFromMap(
      virtualHost: ServerName?,
      identities: Map<ServerName, PskPublicInformation>?,
    ): PskPublicInformation? {
      if (identities != null) {
        return identities[virtualHost]
      }
      return null
    }
  }

  private val lock = ReentrantReadWriteLock()

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
    val credentials = getCredentials(serverNames, identity)
    return if (credentials != null) {
      PskSecretResult(cid, credentials.identity, credentials.key)
    } else {
      PskSecretResult(cid, identity, null)
    }
  }

  /**
   * Get credentials for server name and identity.
   *
   * @param serverNames server name
   * @param identity identity
   * @return credentials, or `null`, if not available.
   */
  private fun getCredentials(
    serverNames: ServerNames?,
    identity: PskPublicInformation?,
  ): PskCredentials? {
    var credentials: PskCredentials? = null

    requireNotNull(identity) { "identity must not be null" }
    lock.readLock().lock()
    try {
      if (serverNames == null) {
        credentials = getPskCredentials(identity, scopedKeys[GLOBAL_SCOPE])
      } else {
        serverNames.forEach { serverName ->
          credentials = getPskCredentials(identity, scopedKeys[serverName])
          if (credentials != null) {
            return@forEach
          }
        }
      }
    } finally {
      lock.readLock().unlock()
    }
    return credentials
  }

  override fun getIdentity(
    peerAddress: InetSocketAddress?,
    virtualHost: ServerNames?,
  ): PskPublicInformation? {
    requireNotNull(peerAddress) { "address must not be null" }
    lock.readLock().lock()
    try {
      if (virtualHost == null) {
        return getIdentityFromMap(GLOBAL_SCOPE, scopedIdentities[peerAddress])
      } else {
        virtualHost.forEach { serverName ->
          val identity = getIdentityFromMap(serverName, scopedIdentities[peerAddress])
          if (identity != null) {
            return identity
          }
        }
      }
    } finally {
      lock.readLock().unlock()
    }
    return null
  }

  override fun setResultHandler(resultHandler: HandshakeResultHandler) {
    // empty implementation
  }

  override fun destroy() {
    lock.writeLock().lock()
    try {
      destroyed = true
      scopedIdentities.clear()
      scopedKeys.values.forEach { keys ->
        keys.values.forEach { credentials ->
          credentials.destroy()
        }
      }
      scopedKeys.clear()
    } finally {
      lock.writeLock().unlock()
    }
  }

  override fun isDestroyed(): Boolean {
    return destroyed
  }

  /**
   * Sets a key value for a given identity.
   *
   * If the key already exists, it will be replaced.
   *
   * @param identity the identity associated with the key
   * @param key the key used to authenticate the identity
   */
  fun setKey(
    identity: String?,
    key: ByteArray?,
  ) = setKey(PskPublicInformation(identity), key, GLOBAL_SCOPE)

  /**
   * Sets a key value for a given identity.
   *
   * If the key already exists, it will be replaced.
   *
   * @param identity the identity associated with the key
   * @param key the key used to authenticate the identity
   */
  fun setKey(
    identity: PskPublicInformation?,
    key: ByteArray?,
  ) = setKey(identity, key, GLOBAL_SCOPE)

  /**
   * Sets a key for an identity scoped to a virtual host.
   *
   * If the key already exists, it will be replaced.
   *
   * @param identity The identity to set the key for.
   * @param key The key to set for the identity.
   * @param virtualHost The virtual host to associate the identity and key with.
   */
  fun setKey(
    identity: String?,
    key: ByteArray?,
    virtualHost: String?,
  ) = setKey(PskPublicInformation(identity), key, ServerName.fromHostName(virtualHost))

  /**
   * Sets a key for an identity scoped to a virtual host.
   *
   * If the key already exists, it will be replaced.
   *
   * @param identity The identity to set the key for
   * @param key The key to set for the identity
   * @param virtualHost The virtual host to associate the identity and key with
   */
  fun setKey(
    identity: PskPublicInformation?,
    key: ByteArray?,
    virtualHost: String?,
  ) = setKey(identity, key, ServerName.fromHostName(virtualHost))

  /**
   * Sets a key for an identity scoped to a virtual host.
   *
   * If the key already exists, it will be replaced.
   *
   * @param identity The identity to set the key for.
   * @param key The key to set for the identity.
   * @param virtualHost The virtual host to associate the identity and key with.
   */
  fun setKey(
    identity: String?,
    key: ByteArray?,
    virtualHost: ServerName?,
  ) = setKey(PskPublicInformation(identity), key, virtualHost)

  /**
   * Sets a key for an identity scoped to a virtual host.
   *
   * If the key already exists, it will be replaced.
   *
   * @param identity the identity to set the key for.
   * @param key The key to set for the identity.
   * @param virtualHost The virtual host to associate the identity and key with.
   */
  fun setKey(
    identity: PskPublicInformation?,
    key: ByteArray?,
    virtualHost: ServerName?,
  ) {
    requireNotNull(identity) { "identity must not be null" }
    requireNotNull(key) { "key must not be null" }
    requireNotNull(virtualHost) { "serverName must not be null" }
    lock.writeLock().lock()
    try {
      var keysForServerName = scopedKeys[virtualHost]
      if (keysForServerName == null) {
        keysForServerName = hashMapOf()
        scopedKeys[virtualHost] = keysForServerName
      }
      keysForServerName[identity] = PskCredentials(identity, key)
    } finally {
      lock.writeLock().unlock()
    }
  }

  /**
   * Adds a shared key for a peer.
   *
   * If the key already exists, it will be replaced.
   *
   * @param peerAddress the IP address and port to use the key for
   * @param identity the PSK identity
   * @param key the shared key
   * @throws NullPointerException if any of the parameters are `null`
   */
  fun addKnownPeer(
    peerAddress: InetSocketAddress?,
    identity: String?,
    key: ByteArray?,
  ) = addKnownPeer(peerAddress, GLOBAL_SCOPE, PskPublicInformation(identity), key)

  /**
   * Adds a shared key for a peer.
   *
   * If the key already exists, it will be replaced.
   *
   * @param peerAddress the IP address and port to use the key for
   * @param identity the PSK identity
   * @param key the shared key
   * @throws NullPointerException if any of the parameters are `null`
   */
  fun addKnownPeer(
    peerAddress: InetSocketAddress?,
    identity: PskPublicInformation?,
    key: ByteArray?,
  ) = addKnownPeer(peerAddress, GLOBAL_SCOPE, identity, key)

  /**
   * Adds a shared key for a virtual host on a peer.
   *
   * If the key already exists, it will be replaced.
   *
   * @param peerAddress the IP address and port to use the key for
   * @param virtualHost the virtual host to use the key for
   * @param identity the PSK identity
   * @param key the shared key
   * @throws NullPointerException if any of the parameters are `null`
   */
  fun addKnownPeer(
    peerAddress: InetSocketAddress?,
    virtualHost: String?,
    identity: String?,
    key: ByteArray?,
  ) = addKnownPeer(peerAddress, ServerName.fromHostName(virtualHost), PskPublicInformation(identity), key)

  /**
   * Adds a shared key for a virtual host on a peer.
   *
   * If the key already exists, it will be replaced.
   *
   * @param peerAddress the IP address and port to use the key for
   * @param virtualHost the virtual host to use the key for
   * @param identity the PSK identity
   * @param key the shared key
   * @throws NullPointerException if any of the parameters are `null`
   */
  fun addKnownPeer(
    peerAddress: InetSocketAddress?,
    virtualHost: String?,
    identity: PskPublicInformation?,
    key: ByteArray?,
  ) = addKnownPeer(peerAddress, ServerName.fromHostName(virtualHost), identity, key)

  fun addKnownPeer(
    peerAddress: InetSocketAddress?,
    virtualHost: ServerName?,
    identity: PskPublicInformation?,
    key: ByteArray?,
  ) {
    requireNotNull(peerAddress) { "peer address must not be null" }
    requireNotNull(virtualHost) { "virtual host must not be null" }
    requireNotNull(identity) { "identity must not be null" }
    requireNotNull(key) { "key must not be null" }
    lock.writeLock().lock()
    try {
      var identities = scopedIdentities[peerAddress]
      if (identities == null) {
        identities = hashMapOf()
        scopedIdentities[peerAddress] = identities
      }
      identities[virtualHost] = identity
      setKey(identity, key, virtualHost)
    } finally {
      lock.writeLock().unlock()
    }
  }

  /**
   * Removes a key value for a given identity.
   *
   * @param identity The identity to remove the key for
   */
  fun removeKey(identity: String?) = removeKey(PskPublicInformation(identity), GLOBAL_SCOPE)

  /**
   * Removes a key value for a given identity.
   *
   * @param identity The identity to remove the key for
   */
  fun removeKey(identity: PskPublicInformation?) = removeKey(identity, GLOBAL_SCOPE)

  /**
   * Removes a key for an identity scoped to a virtual host.
   *
   * @param identity The identity to remove the key for
   * @param virtualHost The virtual host to associate the identity and key with
   */
  fun removeKey(
    identity: String?,
    virtualHost: String?,
  ) = removeKey(PskPublicInformation(identity), ServerName.fromHostName(virtualHost))

  /**
   * Removes a key for an identity scoped to a virtual host.
   *
   * @param identity The identity to remove the key for
   * @param virtualHost The virtual host to associate the identity and key with
   */
  fun removeKey(
    identity: PskPublicInformation?,
    virtualHost: String?,
  ) = removeKey(identity, ServerName.fromHostName(virtualHost))

  /**
   * Removes a key for an identity scoped to a virtual host.
   *
   * @param identity The identity to remove the key for
   * @param virtualHost The virtual host to associate the identity with
   */
  fun removeKey(
    identity: String?,
    virtualHost: ServerName?,
  ) = removeKey(PskPublicInformation(identity), virtualHost)

  /**
   * Removes a key for an identity scoped to a virtual host.
   * @param identity The identity to remove the key for
   * @param virtualHost The virtual host to associate the identity with
   */
  fun removeKey(
    identity: PskPublicInformation?,
    virtualHost: ServerName?,
  ) {
    requireNotNull(identity) { "identity must not be null" }
    requireNotNull(virtualHost) { "serverName must not be null" }
    lock.writeLock().lock()
    try {
      scopedKeys[virtualHost]?.remove(identity)
    } finally {
      lock.writeLock().unlock()
    }
  }
}
