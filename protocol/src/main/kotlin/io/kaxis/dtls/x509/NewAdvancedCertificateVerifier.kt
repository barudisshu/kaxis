/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.x509

import io.kaxis.dtls.CertificateType
import io.kaxis.dtls.ConnectionId
import io.kaxis.dtls.HandshakeResultHandler
import io.kaxis.dtls.ServerNames
import io.kaxis.dtls.message.handshake.CertificateMessage
import io.kaxis.result.CertificateVerificationResult
import java.net.InetSocketAddress
import javax.security.auth.x500.X500Principal

/**
 * New advanced certificate verifier.
 *
 * Returns certificate verification result. If required, the certificate
 * verification result maybe returned asynchronously using a [HandshakeResultHandler]
 *
 * Synchronous example:
 *
 * ```kotlin
 * override fun verifyCertificate(
 *    cid: ConnectionId,
 *    serverName: ServerNames,
 *    clientUsage: Boolean,
 *    truncateCertificatePath: Boolean,
 *    message: CertificateMessage): CertificateVerificationResult {
 *     val verifiedCertificate = ... verify certificate ...
 *     return CertificateVerificationResult(cid, verifiedCertificate, null)
 * }
 * ```
 *
 * Asynchronous example returning the master secret:
 *
 * ```kotlin
 * override fun verifyCertificate(
 *    cid: ConnectionId,
 *    serverName: ServerNames,
 *    clientUsage: Boolean,
 *    truncateCertificatePath: Boolean,
 *    message: CertificateMessage): CertificateVerificationResult {
 *     start ... verify certificate ... // calls processResult with verified certificate path asynchronous
 *     return null  // returns null for asynchronous processing
 * }
 *
 * override fun setResultHandler(resultHandler HandshakeResultHandler) {
 *    this.resultHandler = resultHandler
 * }
 *
 * private fun verifyCertificateAsynchronous(
 *        cid: ConnectionId,
 *        serverName: ServerNames,
 *        clientUsage: Boolean,
 *        truncateCertificatePath: Boolean,
 *        message: CertificateMessage) {
 *     // executed by different thread!
 *     val result = ... verify certificate ...
 *     resultHandler.apply(result)
 * }
 * ```
 */
interface NewAdvancedCertificateVerifier {
  /**
   * Get the list of supported certificate types in order of preference.
   *
   * @return the list of supported certificate types.
   */
  val supportedCertificateTypes: MutableList<CertificateType>

  /**
   * Validates the certificate provided by the peer as part of the certificate message.
   *
   * If a X.509 certificate chain is provided in the certificate message,
   * validate the chain and key usage. If a RawPublicKey certificate is
   * provided, check, if this public key is trusted.
   *
   * @param cid connection ID
   * @param serverNames indicated server names. May be `null`, if not available or SNI is not enabled.
   * @param remotePeer socket address of remote peer.
   * @param clientUsage indicator to check certificate usage. `true`, check key usage for client, `false` for server.
   * @param verifySubject `true` to verify the certificate's subjects, `false`, if not.
   * @param truncateCertificatePath `true` truncate certificate path at a trusted certificate before validation.
   * @param message certificate message to be validated.
   *
   * @return certificate verification result, or `null`, if result is provided asynchronous.
   */
  fun verifyCertificate(
    cid: ConnectionId,
    serverNames: ServerNames,
    remotePeer: InetSocketAddress,
    clientUsage: Boolean,
    verifySubject: Boolean,
    truncateCertificatePath: Boolean,
    message: CertificateMessage,
  ): CertificateVerificationResult

  /**
   * Return a list of certificate authorities which are trusted for authenticating peers.
   *
   * @return a non-null (possibly empty) list of accepted CA issuers.
   */
  val acceptedIssuers: MutableList<X500Principal>

  /**
   * Set the handler for asynchronous handshake results.
   *
   * @param resultHandler handler for asynchronous master secret results. This handler MUST NOT be
   * called from the thread calling [verifyCertificate], instead just return the result there.
   */
  fun setResultHandler(resultHandler: HandshakeResultHandler)
}
