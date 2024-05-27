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
import java.net.InetSocketAddress
import javax.crypto.SecretKey

/**
 * Advanced PSK store with optional asynchronous API.
 *
 * It could also be used to delegate the `master_secret` generation to a HSM.
 *
 * Returns psk secret result instead of PSK's secret key. The secret must either
 * be a master secret (algorithm "MAC"), or a PSK secret key (algorithm "PSK"),
 * If required, the psk secret result maybe returned asynchronously using a [HandshakeResultHandler].
 *
 * **Synchronous example returning the PSK secret key**:
 *
 * ```kotlin
 * override fun generateMasterSecret(
 *  cid: ConnectionId,
 *  serverNames: ServerNames,
 *  identity: PskPublicInformation,
 *  hmacAlgorithm: String,
 *  otherSecret: SecretKey,
 *  seed: ByteArray,
 *  useExtendedMasterSecret) {
 *    val pskSecret = ... func ... identity ... // identity maybe normalized!
 *    return PskSecretResult(cid, identity, pskSecret)
 *  }
 * ```
 */
interface AdvancedPskStore {
  /**
   * Check, if ECDHE PSK cipher suites are supported.
   * @return `true`, if ECDHE PSK cipher suites are supported, `false`, if not.
   */
  fun hasEcdhePskSupported(): Boolean

  /**
   * Request psk secret result.
   *
   * Either return the result, or `null` and process the request asynchronously.
   * The [PskSecretResult] must contain the CID, the normalized identity and
   * master secret or PSK secret key, if available. If the result is not returned,
   * it is passed asynchronously to the result handler, provided during initialization
   * by [setResultHandler].
   *
   * @param cid connection id for stateless asynchronous implementations.
   * @param serverNames server names. Maybe `null`, if SNI is not enabled or not used by the client.
   * @param identity psk identity. Maybe normalized, if identity is available in the store.
   * @param hmacAlgorithm HMAC algorithm name for PRF.
   * @param otherSecret other secret from ECDHE, or `null`. Must be cloned for asynchronous use.
   * see [RFC 5489, other secret](https://tools.ietf.org/html/rfc5489#page-4).
   * @param seed seed for PRF.
   * @param useExtendedMasterSecret If the master secret is created, `true`, creates extended
   * master secret (RFC 7627), `false`, creates master secret (RFC 5246).
   * @return psk secret result, or `null`, if result is provided asynchronous.
   */
  fun requestPskSecretResult(
    cid: ConnectionId,
    serverNames: ServerNames?,
    identity: PskPublicInformation,
    hmacAlgorithm: String,
    otherSecret: SecretKey?,
    seed: ByteArray,
    useExtendedMasterSecret: Boolean,
  ): PskSecretResult?

  /**
   * Gets the _identity_ to use for a PSK based handshake with a given peer.
   *
   * A DTLS client uses this method to determine the identity to include in its _CLIENT_KEY_EXCHANGE_
   * message during a PSK based DTLS handshake with the peer.
   *
   * @param peerAddress The IP address and port of the peer to perform the handshake with.
   * @param virtualHost the virtual host at the peer to connect to. If `null`, the identity will
   * be looked up in the global scope.
   *
   * @return The identity to use or `null` if no peer with the given address and virtual host is registered.
   * @throws NullPointerException if address is `null`.
   */
  fun getIdentity(
    peerAddress: InetSocketAddress?,
    virtualHost: ServerNames?,
  ): PskPublicInformation?

  /**
   * Set the handler for asynchronous master secret results. Called during initialization.
   * Synchronous implementations may just ignore this using an empty implementation.
   *
   * @param resultHandler handler for asynchronous master secret results. This handler
   * MUST NOT be called from the thread calling [requestPskSecretResult], instead just
   * return the result there.
   */
  fun setResultHandler(resultHandler: HandshakeResultHandler)
}
