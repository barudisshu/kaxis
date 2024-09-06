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

import io.kaxis.dtls.*
import io.kaxis.dtls.cipher.*
import io.kaxis.result.CertificateIdentityResult
import javax.security.auth.x500.X500Principal

/**
 * Certificate identity provider.
 *
 * One of the complex functions in (D)TLS is the negotiation of the crypto
 * parameters. That includes also to select the right certificate chain for the
 * proposed parameters of the client. The large variety of these parameters
 * makes it hard.
 *
 * For CoAP this is simplified by [RFC 7252, 9.1 DTLS-Secured CoAP]
 * (https://datatracker.ietf.org/doc/html/rfc7252#section-9.1) using common sets
 * of mandatory supported crypto parameter values for the different security
 * cases. That makes it easier for clients to successfully negotiate a DTLS
 * session and for the server to offer the right selection of supported parameters.
 *
 * If [PSK](https://datatracker.ietf.org/doc/html/rfc7252#section-9.1.3.1) is used,
 * the cipher suite [CipherSuite.TLS_PSK_WITH_AES_128_CCM_8] is mandatory to
 * implement.
 *
 * If [PSK](https://datatracker.ietf.org/doc/html/rfc7252#section-9.1.3.2) is used,
 * the cipher suite [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8] is mandatory
 * to implement. The Elliptic curve: secp256r1 (0x0017) and SHA256withECDSA are
 * also mandatory to support.
 *
 * If [X509](https://datatracker.ietf.org/doc/html/rfc7252#section-9.1.3.3) is used,
 * the cipher suite [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8] is mandatory
 * to implement. The Elliptic curve: secp256r1 (0x0017) and SHA256withECDSA are
 * also mandatory to support.
 *
 * For simple setups [SingleCertificateProvider] will do the job. But for
 * serveral reason, the simple world of CoAP doesn't always fit into reality. On
 * the "old" side, some certificates on the path may be RSA based, on the "new"
 * Ed25519/Ed448 may be preferred. With that, it starts to get complex again,
 * and a server may require more different certificate paths to support
 * different clients. This provider interface helps to overcome this. It enables
 * to select the used certificates based on the related crypto parameter, server
 * name, and issuer.
 *
 * Using X.509 comes also with some more asymmetry: to use a certificate chain
 * for authentication, the sending peer is only required to support signing for
 * the node certificate's public key. For the all the issuer signatures the
 * support is only relevant for the receiving side.Kaxis's default configuration
 * implementation does always a full check, regardless of only sending the
 * certificates.
 */
interface CertificateProvider {
  /**
   * Gets the list of supported certificate key algorithms.
   *
   * @return the list of supported certificate key algorithms.
   */
  val supportedCertificateKeyAlgorithms: MutableList<CipherSuite.CertificateKeyAlgorithm>?

  /**
   * Get the list of supported certificate types in order of preference.
   *
   * @return the list of supported certificate types.
   */
  val supportedCertificateTypes: MutableList<CertificateType>?

  /**
   * Get the certificate identity.
   *
   * If multiple certificate identities are matching the criteria, the order
   * of the signature and hash algorithms should be used to select the one to
   * be used for the handshake. If lists are `null` or empty, it's not
   * used to choose a certificate identity.
   *
   * @param cid connection ID
   * @param client `true`, for client side certificates, `false`, for server side certificates.
   * @param issuers list of trusted issuers. May be `null` or empty.
   * @param serverNames indicated server names. May be `null` or empty,
   * if not available or SNI is not enabled.
   * @param certificateKeyAlgorithms list of list of certificate key algorithms
   * to select a node's certificate. May be `null` or empty.
   * @param signatureAndHashAlgorithms signatures and hash algorithms. May be `null` or empty.
   * @param curves ec-curves (supported groups). May be `null` or empty.
   *
   * @return certificate identity result, or `null`, if result is provided asynchronous.
   */
  fun requestCertificateIdentity(
    cid: ConnectionId,
    client: Boolean,
    issuers: MutableList<X500Principal>?,
    serverNames: ServerNames?,
    certificateKeyAlgorithms: MutableList<CipherSuite.CertificateKeyAlgorithm>?,
    signatureAndHashAlgorithms: MutableList<SignatureAndHashAlgorithm>?,
    curves: MutableList<XECDHECryptography.SupportedGroup>?,
  ): CertificateIdentityResult

  /**
   * Set the handler for asynchronous handshake results.
   *
   * Called during initialization of the synchronous implementations may just ignore this
   * using an empty implementation.
   *
   * @param resultHandler handler for asynchronous master secret results. This handler
   * MUST NOT be called from the thread calling [requestCertificateIdentity], instead
   * just return the result there.
   */
  fun setResultHandler(resultHandler: HandshakeResultHandler)
}
