/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.x509.provider

import io.kaxis.JceProvider
import io.kaxis.dtls.*
import io.kaxis.dtls.cipher.CipherSuite
import io.kaxis.dtls.cipher.XECDHECryptography
import io.kaxis.dtls.x509.CertificateConfigurationHelper
import io.kaxis.dtls.x509.CertificateProvider
import io.kaxis.dtls.x509.ConfigurationHelperSetup
import io.kaxis.ext.addIfAbsent
import io.kaxis.result.CertificateIdentityResult
import io.kaxis.util.Asn1DerDecoder
import io.kaxis.util.CertPathUtil
import org.slf4j.LoggerFactory
import java.security.cert.X509Certificate
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.X509KeyManager
import javax.security.auth.x500.X500Principal

/**
 * Example certificate identity provider based on a [X509KeyManager].
 *
 * Selects the certificate based on the issuers and server name, if provided.
 * The provided signature and hash algorithms and the supported curves are also
 * considered. If more than one certificate fits, the provided signature and
 * hash algorithms are used the select the best fit.
 *
 * It May be used as a template to implement a solution for more specific use-cases.
 */
class KeyManagerCertificateProvider : CertificateProvider, ConfigurationHelperSetup {
  companion object {
    private val LOGGER = LoggerFactory.getLogger(KeyManagerCertificateProvider::class.java)
    private val ID = AtomicInteger()

    /**
     * Special Bouncy Castle key types for server credentials.
     */
    private val BC_SERVER_KEY_TYPES_MAP = hashMapOf<String, String>()

    init {
      BC_SERVER_KEY_TYPES_MAP[JceProvider.EC] = "ECDHE_ECDSA"
      BC_SERVER_KEY_TYPES_MAP[JceProvider.RSA] = "ECDHE_RSA"
    }

    /**
     * Key types for credentials.
     */
    private val ALL_KEY_TYPES =
      listOf(JceProvider.EC, JceProvider.RSA, JceProvider.EDDSA, JceProvider.ED25519, JceProvider.ED448)

    private fun addEdDsaSupport(
      publicKeyTypes: MutableList<String>,
      signatureAndHashAlgorithms: List<SignatureAndHashAlgorithm>,
    ) {
      if (signatureAndHashAlgorithms.contains(SignatureAndHashAlgorithm.INTRINSIC_WITH_ED25519)) {
        publicKeyTypes.addIfAbsent(JceProvider.EDDSA)
        publicKeyTypes.addIfAbsent(JceProvider.ED25519)
      }
      if (signatureAndHashAlgorithms.contains(SignatureAndHashAlgorithm.INTRINSIC_WITH_ED448)) {
        publicKeyTypes.addIfAbsent(JceProvider.EDDSA)
        publicKeyTypes.addIfAbsent(JceProvider.ED448)
      }
    }

    private fun asList(types: Array<CertificateType>?): MutableList<CertificateType>? {
      if (types.isNullOrEmpty()) {
        return null
      }
      return types.toMutableList()
    }
  }

  /**
   * Default alias. May be `null`.
   */
  val defaultAlias: String?

  /**
   * Key manager.
   */
  val keyManager: X509KeyManager

  /**
   * Instance ID for logging.
   */
  val id: Int

  /**
   * List of supported certificate type in order of preference.
   */
  override val supportedCertificateTypes: MutableList<CertificateType>

  /**
   * List of supported certificate key algorithms.
   */
  override val supportedCertificateKeyAlgorithms: MutableList<CipherSuite.CertificateKeyAlgorithm>

  /**
   * Enable key pairs verification. Check, if key-pairs are supported by JCE and public keys are
   * corresponding to the private keys. Enabled by default.
   */
  var verifyKeyPairs: Boolean = true

  /**
   * Create certificate provider based on key manager.
   *
   * @param keyManager key manager with certificates and private keys.
   * @param supportedCertificateTypes list of supported certificate types ordered by preference.
   * @throws NullPointerException if the key manager is `null`
   * @throws IllegalArgumentException if list of certificate types is empty or contains unsupported types.
   */
  constructor(
    keyManager: X509KeyManager?,
    supportedCertificateTypes: MutableList<CertificateType>?,
  ) : this(
    null,
    keyManager,
    supportedCertificateTypes,
  )

  /**
   * Create certificate provider based on key manager with default alias.
   *
   * @param defaultAlias default alias. May be `null`.
   * @param keyManager key manager with certificates and private keys.
   * @param supportedCertificateTypes list of supported certificate types ordered by preference.
   * @throws NullPointerException if the key manager is `null`
   * @throws IllegalArgumentException if list of certificate types is empty or contains unsupported types.
   */
  constructor(
    defaultAlias: String?,
    keyManager: X509KeyManager?,
    supportedCertificateTypes: MutableList<CertificateType>?,
  ) {
    requireNotNull(keyManager) { "KeyManager must not be null!" }
    if (supportedCertificateTypes != null) {
      require(supportedCertificateTypes.isNotEmpty()) { "Certificate types must not be empty!" }
      supportedCertificateTypes.forEach { certificateType ->
        require(certificateType.isSupported) { "Certificate type $certificateType is not supported!" }
      }
    }
    this.id = ID.incrementAndGet()
    this.defaultAlias = defaultAlias
    this.keyManager = keyManager
    var supportedCertificateTypes0 = supportedCertificateTypes
    if (supportedCertificateTypes0 == null) {
      // default X.509
      supportedCertificateTypes0 = ArrayList(1)
      supportedCertificateTypes0.add(CertificateType.X_509)
    }
    this.supportedCertificateTypes = Collections.unmodifiableList(supportedCertificateTypes0)
    val supportedCertificateKeyAlgorithms = mutableListOf<CipherSuite.CertificateKeyAlgorithm>()
    var aliases = getAliases(false, ALL_KEY_TYPES, null)
    aliases.forEach { alias ->
      setup(alias, supportedCertificateKeyAlgorithms)
    }
    aliases = getAliases(true, ALL_KEY_TYPES, null)
    aliases.forEach { alias ->
      setup(alias, supportedCertificateKeyAlgorithms)
    }
    this.supportedCertificateKeyAlgorithms = Collections.unmodifiableList(supportedCertificateKeyAlgorithms)
  }

  /**
   * Enable/Disable the verification of the provided key pairs.
   *
   * @param enable `true` to enable verification (default), `false`, to disable it.
   * @return this certificate provider for command chaining.
   */
  fun setVerifyKeyPairs(enable: Boolean): KeyManagerCertificateProvider {
    this.verifyKeyPairs = enable
    return this
  }

  private fun setup(
    alias: String,
    supportedCertificateKeyAlgorithms: MutableList<CipherSuite.CertificateKeyAlgorithm>,
  ) {
    val certificateChain = keyManager.getCertificateChain(alias)
    if (!certificateChain.isNullOrEmpty()) {
      val key = certificateChain[0].publicKey
      val keyAlgorithm = CipherSuite.CertificateKeyAlgorithm.getAlgorithm(key)
      supportedCertificateKeyAlgorithms.addIfAbsent(keyAlgorithm)
    }
  }

  override fun setupConfigurationHelper(helper: CertificateConfigurationHelper?) {
    requireNotNull(helper) { "Certificate configuration helper must not be null!" }
    var aliases = getAliases(false, ALL_KEY_TYPES, null)
    aliases.forEach { alias ->
      setupConfigurationHelperForAlias(helper, alias)
    }
    aliases = getAliases(true, ALL_KEY_TYPES, null)
    aliases.forEach { alias ->
      setupConfigurationHelperForAlias(helper, alias)
    }
  }

  /**
   * Setup [supportedCertificateKeyAlgorithms] adn the optional configuration helper using the
   * credentials of the provided alias.
   *
   * @param helper configuration helper. May be `null`.
   * @param alias alias of the credentials.
   */
  private fun setupConfigurationHelperForAlias(
    helper: CertificateConfigurationHelper?,
    alias: String,
  ) {
    val certificateChain = keyManager.getCertificateChain(alias)
    if (!certificateChain.isNullOrEmpty()) {
      try {
        helper?.verifyKeyPair(keyManager.getPrivateKey(alias), certificateChain[0].publicKey)
      } catch (ex: IllegalArgumentException) {
        if (verifyKeyPairs) {
          throw IllegalStateException(ex.message)
        } else {
          LOGGER.warn("Mismatching key-pair, causing failure then used!", ex)
        }
      }
      if (supportedCertificateTypes.contains(CertificateType.X_509)) {
        helper?.addConfigurationDefaultsFor(certificateChain.toMutableList())
      } else if (supportedCertificateTypes.contains(CertificateType.RAW_PUBLIC_KEY)) {
        helper?.addConfigurationDefaultsFor(certificateChain[0].publicKey)
      }
    }
  }

  override fun requestCertificateIdentity(
    cid: ConnectionId,
    client: Boolean,
    issuers: MutableList<X500Principal>?,
    serverNames: ServerNames?,
    certificateKeyAlgorithms: MutableList<CipherSuite.CertificateKeyAlgorithm>?,
    signatureAndHashAlgorithms: MutableList<SignatureAndHashAlgorithm>?,
    curves: MutableList<XECDHECryptography.SupportedGroup>?,
  ): CertificateIdentityResult {
    val role = if (client) "Client" else "Server"
    LOGGER.debug("[{}]: {} certificate for {}", id, role, serverNames ?: "<n.a.>")
    if (!issuers.isNullOrEmpty()) {
      LOGGER.debug("[{}]: {} certificate issued by {}", id, role, issuers)
    }
    val principals = issuers?.toTypedArray()
    val keyTypes = mutableListOf<String>()
    certificateKeyAlgorithms?.forEach { algorithm ->
      if (algorithm != CipherSuite.CertificateKeyAlgorithm.NONE) {
        keyTypes.addIfAbsent(algorithm.name)
      }
    }
    if (!signatureAndHashAlgorithms.isNullOrEmpty()) {
      if (keyTypes.isEmpty()) {
        if (SignatureAndHashAlgorithm.isSupportedAlgorithm(signatureAndHashAlgorithms, JceProvider.EC)) {
          keyTypes.addIfAbsent(JceProvider.EC)
        }
        if (SignatureAndHashAlgorithm.isSupportedAlgorithm(signatureAndHashAlgorithms, JceProvider.RSA)) {
          keyTypes.addIfAbsent(JceProvider.RSA)
        }
        addEdDsaSupport(keyTypes, signatureAndHashAlgorithms)
      } else if (keyTypes.contains(JceProvider.EC)) {
        addEdDsaSupport(keyTypes, signatureAndHashAlgorithms)
      }
    } else if (keyTypes.isEmpty()) {
      keyTypes.add(JceProvider.EC)
    }

    LOGGER.debug("[{}]: {} certificate public key types {}", id, role, keyTypes)
    if (!signatureAndHashAlgorithms.isNullOrEmpty()) {
      LOGGER.debug("[{}]: {} certificate signed with {}", id, role, signatureAndHashAlgorithms)
    }
    if (!curves.isNullOrEmpty()) {
      LOGGER.debug("[{}]: {} certificate using {}", id, role, curves)
    }

    var aliases = getAliases(client, keyTypes, principals)
    if (aliases.isNotEmpty()) {
      val matchingServerNames = mutableListOf<String>()
      val matchingNodeSignatures = mutableListOf<String>()
      val matchingChainSignatures = mutableListOf<String>()
      val matchingCurves = mutableListOf<String>()
      // after issuers, check the server_names
      var index = 1
      aliases.forEach { alias ->
        LOGGER.debug("[{}]: {} apply select {} - {} of {}", id, role, alias, index, aliases.size)
        val certificateChain = keyManager.getCertificateChain(alias)
        val nodeCertificate = certificateChain[0]
        val chain = certificateChain.toMutableList()
        if (serverNames != null && matchServerNames(serverNames, nodeCertificate)) {
          matchingServerNames.add(alias)
        }
        if (signatureAndHashAlgorithms != null &&
          matchNodeSignatureAndHashAlgorithms(
            signatureAndHashAlgorithms,
            nodeCertificate,
          )
        ) {
          matchingNodeSignatures.add(alias)
        }
        if (signatureAndHashAlgorithms != null &&
          matchChainSignatureAndHashAlgorithms(
            signatureAndHashAlgorithms,
            chain,
          )
        ) {
          matchingChainSignatures.add(alias)
        }
        if (curves != null && matchCurves(curves, chain)) {
          matchingCurves.add(alias)
        }
        ++index
      }

      if (matchingServerNames.isNotEmpty()) {
        LOGGER.debug("[{}]: {} selected {} by {}", id, role, matchingServerNames.size, serverNames)
        aliases.retainAll(matchingServerNames)
      }
      if (signatureAndHashAlgorithms != null) {
        LOGGER.debug(
          "[{}]: {} selected {} by the node's signature and hash algorithms",
          id,
          role,
          matchingNodeSignatures.size,
        )
        LOGGER.debug(
          "[{}]: {} selected {} by the chain signature and hash algorithms",
          id,
          role,
          matchingNodeSignatures.size,
        )
        aliases.retainAll(matchingNodeSignatures)
        if (supportedCertificateTypes.contains(CertificateType.X_509)) {
          var temp: MutableList<String>? = null
          if (supportedCertificateTypes.contains(CertificateType.RAW_PUBLIC_KEY)) {
            temp = aliases
          }
          aliases.retainAll(matchingChainSignatures)
          if (aliases.isEmpty() && temp != null) {
            aliases = temp
          }
        }
      }
      if (curves != null) {
        LOGGER.debug("[{}]: {} selected {} by curves", id, role, matchingCurves.size)
        aliases.retainAll(matchingCurves)
      }
      if (aliases.isNotEmpty()) {
        if (aliases.size > 1 && signatureAndHashAlgorithms != null && signatureAndHashAlgorithms.size > 1) {
          aliases = selectPriorized(aliases, signatureAndHashAlgorithms)
        }
        val id: String =
          if (aliases.size > 1 && defaultAlias != null && aliases.contains(defaultAlias)) {
            defaultAlias
          } else {
            aliases[0]
          }
        val certificateChain = keyManager.getCertificateChain(id)
        val chain = certificateChain.toMutableList()
        val privateKey = keyManager.getPrivateKey(id)
        return CertificateIdentityResult(cid, privateKey, chain)
      } else {
        LOGGER.debug("[{}]: {} no matching credentials left!", id, role)
      }
    } else {
      LOGGER.debug("[{}]: no matching credentials", id)
    }

    return CertificateIdentityResult(cid)
  }

  override fun setResultHandler(resultHandler: HandshakeResultHandler) {
    // empty implementation
  }

  /**
   * Get aliases for matching credentials.
   *
   * @param client `true`, for client side certificates, `false`, for server side certificates.
   * @param keyTypes list of key types.
   * @param issuers list of trusted issuers. May be `null`.
   *
   * @return list of aliases to matching credentials. Empty, if no matching credentials are found.
   */
  private fun getAliases(
    client: Boolean,
    keyTypes: List<String>,
    issuers: Array<X500Principal>?,
  ): MutableList<String> {
    val all = mutableListOf<String>()
    keyTypes.forEach { keyType ->
      val alias: Array<String>? =
        if (client) {
          keyManager.getClientAliases(keyType, issuers)
        } else {
          keyManager.getServerAliases(keyType, issuers)
        }
      if (alias != null) {
        LOGGER.debug("[{}]: {} found {} {} keys", id, if (client) "client" else "server", alias.size, keyType)
        all.addIfAbsent(alias.toMutableList())
      } else {
        LOGGER.debug("[{}]: {} found no {} keys", id, if (client) "client" else "server", keyType)
      }
    }
    return all
  }

  /**
   * Check, if provided node certificate matches the serverNames.
   *
   * @param serverNames server names
   * @param node node certificate
   * @return `true`, if matching, `false`, if not.
   */
  private fun matchServerNames(
    serverNames: ServerNames,
    node: X509Certificate,
  ): Boolean {
    val serverName = serverNames.getServerName(ServerName.NameType.HOST_NAME)
    return if (serverName != null) {
      // currently only hostnames are defined (and supported)
      val name = serverName.nameAsString
      CertPathUtil.matchDestination(node, name)
    } else {
      false
    }
  }

  /**
   * Checks, if provided certificate chain matches the signature and hash algorithms.
   *
   * @param signatureAndHashAlgorithms list of signature and hash algorithms
   * @param chain the certificate chain to check
   * @return `true`, if matching, `false`, if not.
   */
  private fun matchChainSignatureAndHashAlgorithms(
    signatureAndHashAlgorithms: MutableList<SignatureAndHashAlgorithm>,
    chain: MutableList<X509Certificate>,
  ): Boolean {
    return SignatureAndHashAlgorithm.isSignedWithSupportedAlgorithms(signatureAndHashAlgorithms, chain)
  }

  /**
   * Checks, if provided node certificate matches the signature and hash algorithms.
   *
   * @param signatureAndHashAlgorithms list of signature and hash algorithms
   * @param node the node's certificate to check
   *
   * @return `true`, if matching, `false`, if not.
   */
  private fun matchNodeSignatureAndHashAlgorithms(
    signatureAndHashAlgorithms: MutableList<SignatureAndHashAlgorithm>,
    node: X509Certificate?,
  ): Boolean {
    return SignatureAndHashAlgorithm.getSupportedSignatureAlgorithm(signatureAndHashAlgorithms, node?.publicKey) != null
  }

  /**
   * Checks, if provided certificate chain matches the curves.
   *
   * @param curves list of supported groups (curves)
   * @param chain the certificate chain to check
   *
   * @return `true`, if matching, `false`, if not.
   */
  private fun matchCurves(
    curves: List<XECDHECryptography.SupportedGroup>?,
    chain: List<X509Certificate>?,
  ): Boolean {
    chain?.forEach { certificate ->
      val certPublicKey = certificate.publicKey
      if (Asn1DerDecoder.isEcBased(certPublicKey.algorithm)) {
        val group = XECDHECryptography.SupportedGroup.fromPublicKey(certPublicKey) ?: return false
        if (curves?.contains(group) != true) {
          return false
        }
      }
    }
    return true
  }

  /**
   * Select the set of aliases, which node certificate matches the first matching signature and hash algorithms.
   *
   * @param alias preselected aliases
   * @param signatureAndHashAlgorithms list of signature and hash algorithms ordered by priority
   *
   * @return (sub) set of aliases matching the first matching signature and hash algorithms in the ordered list.
   */
  private fun selectPriorized(
    alias: List<String>?,
    signatureAndHashAlgorithms: List<SignatureAndHashAlgorithm>?,
  ): MutableList<String> {
    val result = mutableListOf<String>()
    signatureAndHashAlgorithms?.forEach { signatureAndHashAlgorithm ->
      alias?.forEach { id ->
        val certificateChain = keyManager.getCertificateChain(id)
        if (!certificateChain.isNullOrEmpty()) {
          val algorithm = certificateChain[0].publicKey.algorithm
          if (signatureAndHashAlgorithm.isSupported(algorithm)) {
            result.add(id)
            LOGGER.debug("Select by signature {} - {} == {}", id, signatureAndHashAlgorithm.jcaName, algorithm)
          } else {
            LOGGER.debug("Signature doesn't match {} - {} != {}", id, signatureAndHashAlgorithm.jcaName, algorithm)
          }
        }
      }
      if (result.isNotEmpty()) {
        return@forEach
      }
    }

    return result
  }
}
