/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.x509

import io.kaxis.JceProvider
import io.kaxis.dtls.SignatureAndHashAlgorithm
import io.kaxis.dtls.cipher.XECDHECryptography
import io.kaxis.ext.addIfAbsent
import io.kaxis.util.Asn1DerDecoder
import io.kaxis.util.CertPathUtil
import java.security.GeneralSecurityException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate

/**
 * Certificate configuration helper.
 *
 * Estimating the proper signature and hash algorithms and the supported curves
 * for ECDSA/ECDHE is implemented here.
 *
 * For all public keys passed to [addConfigurationDefaultsFor], the
 * supported curve, and a signature and hash algorithm is added to the default
 * parameters.
 */
class CertificateConfigurationHelper {
  /**
   * List of provided public keys.
   */
  private val keys: MutableList<PublicKey> = arrayListOf()

  /**
   * List of provided certificate chains.
   *
   */
  private val chains: MutableList<MutableList<X509Certificate>> = arrayListOf()

  /**
   * List of provided trusted certificates.
   */
  private val trusts: MutableList<X509Certificate> = arrayListOf()

  /**
   * Indicates, that one of the node's certificates provided with [addConfigurationDefaultsFor] supports the usage for clients.
   */
  private var clientUsage: Boolean = false

  /**
   * Indicates, that one of the node's certificates provided with [addConfigurationDefaultsFor] supports the usage for servers.
   */
  private var serverUsage: Boolean = false

  /**
   * List of supported signature and hash algorithms.
   */
  val defaultSignatureAndHashAlgorithms: MutableList<SignatureAndHashAlgorithm> = arrayListOf()

  /**
   * List of supported groups.
   */
  val defaultSupportedGroups: MutableList<XECDHECryptography.SupportedGroup> = arrayListOf()

  /**
   * Add parameters for the provided public key.
   *
   * The support curve and a signature and hash algorithm are added
   * to the default parameters.
   *
   * @param key the public key to add
   * @throws IllegalArgumentException if the public key is not supported
   */
  fun addConfigurationDefaultsFor(key: PublicKey) {
    val algorithm = key.algorithm
    require(JceProvider.isSupported(algorithm)) { "Public key algorithm $algorithm is not supported!" }
    if (Asn1DerDecoder.isEcBased(algorithm)) {
      val group = XECDHECryptography.SupportedGroup.fromPublicKey(key)
      require(group != null) { "Public key's ec-group must be supported!" }
      if (!defaultSupportedGroups.contains(group)) {
        defaultSupportedGroups.add(group)
      }
    }
    SignatureAndHashAlgorithm.ensureSignatureAlgorithm(defaultSignatureAndHashAlgorithms, key)
    keys.addIfAbsent(key)
    if (!keys.contains(key)) {
      keys.add(key)
    }
  }

  fun addConfigurationDefaultsFor(certificateChain: Array<X509Certificate>?) {
    addConfigurationDefaultsFor(certificateChain?.toMutableList())
  }

  /**
   * Add parameters for the provided certificate chain.
   *
   * The public key of the head certificate (node's certificate) is passed to
   * [addConfigurationDefaultsFor]. Also all used signature and hash algorithms
   * in the certificate chain are added to the defaults parameters.
   * And all used curves of public keys in the chain are added to the default
   * parameters as well.
   *
   * @param certificateChain the certificate chain to add
   * @throws IllegalArgumentException if a public key or signature and hash
   * algorithms is not supported
   */
  fun addConfigurationDefaultsFor(certificateChain: MutableList<X509Certificate>?) {
    if (!certificateChain.isNullOrEmpty()) {
      var certificate = certificateChain[0]
      addConfigurationDefaultsFor(certificate.publicKey)
      if (CertPathUtil.canBeUsedForAuthentication(certificate, false)) {
        serverUsage = true
      }
      if (CertPathUtil.canBeUsedForAuthentication(certificate, true)) {
        clientUsage = true
      }
      defaultSignatureAndHashAlgorithms.addIfAbsent(SignatureAndHashAlgorithm.getSignatureAlgorithms(certificateChain))
      for (index in 1..<certificateChain.size) {
        certificate = certificateChain[index]
        val certPublicKey = certificate.publicKey
        if (Asn1DerDecoder.isEcBased(certPublicKey.algorithm)) {
          val group = XECDHECryptography.SupportedGroup.fromPublicKey(certPublicKey)
          requireNotNull(group) { "CA's public key ec-group must be supported!" }
          defaultSupportedGroups.addIfAbsent(group)
        }
      }
      chains.add(certificateChain)
    }
  }

  /**
   * Add parameters for the provided certificate chain.
   *
   * The public key of the head certificate (node's certificate) is passed to
   * [addConfigurationDefaultsFor]. Also all used signature and hash algorithms
   * in the certificate chain are added to the defaults parameters. And all
   * used curves of public keys in the chain are added to the default parameters
   * as well.
   *
   * @param certificateChain the certificate chain to add
   * @throws IllegalArgumentException if a public key or signature and hash algorithm is not supported
   */
  fun addConfigurationDefaultsForTrusts(certificateChain: MutableList<X509Certificate>?) {
    if (!certificateChain.isNullOrEmpty()) {
      var certificate = certificateChain[0]
      addConfigurationDefaultsFor(certificate.publicKey)
      if (CertPathUtil.canBeUsedForAuthentication(certificate, false)) {
        serverUsage = true
      }
      if (CertPathUtil.canBeUsedForAuthentication(certificate, true)) {
        clientUsage = true
      }
      defaultSignatureAndHashAlgorithms.addIfAbsent(SignatureAndHashAlgorithm.getSignatureAlgorithms(certificateChain))

      for (index in 1..<certificateChain.size) {
        certificate = certificateChain[index]
        val certPublicKey = certificate.publicKey
        if (Asn1DerDecoder.isEcBased(certPublicKey.algorithm)) {
          val group = XECDHECryptography.SupportedGroup.fromPublicKey(certPublicKey)
          requireNotNull(group) { "CA's public key ec-group must be supported!" }
          defaultSupportedGroups.addIfAbsent(group)
        }
      }

      chains.add(certificateChain)
    }
  }

  /**
   * Add parameters for the provided trusted certificates.
   *
   * The supported curve and a signature and hash algorithms of all public keys
   * are added to the default parameters.
   */
  fun addConfigurationDefaultsForTrusts(trusts: Array<X509Certificate>?) {
    trusts?.forEach { certificate ->
      addConfigurationDefaultsForTrusts(certificate.publicKey)
      this.trusts.add(certificate)
    }
  }

  /**
   * Add parameters for the provided trusted public kye.
   *
   * The supported curve and a signature and hash algorithm are added to the default parameters.
   *
   * @param publicKey trusted public key
   */
  fun addConfigurationDefaultsForTrusts(publicKey: PublicKey?) {
    if (publicKey != null) {
      SignatureAndHashAlgorithm.ensureSignatureAlgorithm(defaultSignatureAndHashAlgorithms, publicKey)
      if (Asn1DerDecoder.isEcBased(publicKey.algorithm)) {
        val group = XECDHECryptography.SupportedGroup.fromPublicKey(publicKey)
        requireNotNull(group) { "CA's public key ec-group must be supported!" }
        defaultSupportedGroups.addIfAbsent(group)
      }
    }
  }

  /**
   * Verify the provided algorithms match the added public key, certificate chains and trusted certificates.
   * @param algorithms list of configured signature and hash algorithms
   */
  fun verifySignatureAndHashAlgorithmsConfiguration(algorithms: MutableList<SignatureAndHashAlgorithm>) {
    keys.forEach { key ->
      checkNotNull(SignatureAndHashAlgorithm.getSupportedSignatureAlgorithm(algorithms, key)) {
        "supported signature and hash algorithms $algorithms doesn't match the public ${key.algorithm} key!"
      }
    }

    chains.forEach { chain ->
      check(SignatureAndHashAlgorithm.isSignedWithSupportedAlgorithms(algorithms, chain)) {
        "supported signature and hash algorithms $algorithms doesn't match the certificate chains!"
      }
    }

    trusts.forEach { trust ->
      val publicKey = trust.publicKey
      checkNotNull(SignatureAndHashAlgorithm.getSupportedSignatureAlgorithm(algorithms, publicKey)) {
        "supported signature and hash algorithms " +
          "$algorithms doesn't match the trust's public key ${publicKey.algorithm}!"
      }
    }
  }

  /**
   * Verify the provided groups match the added public key and trusted certificates.
   * @param groups list of configured supported groups
   */
  fun verifySupportedGroupsConfiguration(groups: List<XECDHECryptography.SupportedGroup>) {
    defaultSupportedGroups.forEach { group ->
      check(group.isUsable) { "public key used with unsupported group (curve) ${group.name}!" }
      check(groups.contains(group)) { "public key used with not configured group (curve) ${group.name}!" }
    }
  }

  /**
   * Checks, if one of the node certificates of the added chains can be used in a specific role.
   * @param client `true`, for client role, `false`, for server role.
   * @return `true`, if role is supported, `false`, if not.
   */
  fun canBeusedForAuthentication(client: Boolean): Boolean {
    return chains.isEmpty() || (if (client) clientUsage else serverUsage)
  }

  /**
   * Verify the provided key pair.
   *
   * @param privateKey private key
   * @param publicKey public key
   * @throws IllegalArgumentException if key pair is not valid or not supported by the JCE.
   */
  @Suppress("kotlin:S3776")
  fun verifyKeyPair(
    privateKey: PrivateKey,
    publicKey: PublicKey,
  ) {
    val algorithm = publicKey.algorithm
    SignatureAndHashAlgorithm.SignatureAlgorithm.entries.forEach { signatureAlgorithm ->
      if (signatureAlgorithm.isSupported(algorithm)) {
        var signatureAndHashAlgorithm =
          SignatureAndHashAlgorithm(SignatureAndHashAlgorithm.HashAlgorithm.INTRINSIC, signatureAlgorithm)
        if (!signatureAlgorithm.isIntrinsic) {
          SignatureAndHashAlgorithm.HashAlgorithm.entries.forEach hash@{ hashAlgorithm ->
            if (SignatureAndHashAlgorithm.HashAlgorithm.INTRINSIC != hashAlgorithm &&
              SignatureAndHashAlgorithm.HashAlgorithm.NONE != hashAlgorithm
            ) {
              signatureAndHashAlgorithm = SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm)
              if (signatureAndHashAlgorithm.isSupported) {
                return@hash
              }
            }
          }
        }
        if (signatureAndHashAlgorithm.isSupported(publicKey)) {
          val threadLocalSignature = signatureAndHashAlgorithm.getThreadLocalSignature()
          val signature =
            threadLocalSignature.current() ?: throw GeneralSecurityException(
              "thread local signature is not supported!",
            )
          val data = "Just a signature test".toByteArray()
          try {
            signature.initSign(privateKey)
            signature.update(data)
            val sign = signature.sign()

            signature.initVerify(publicKey)
            signature.update(data)
            if (signature.verify(sign)) {
              // key pair verified
              return
            }
            throw IllegalArgumentException("${publicKey.algorithm} key pair is not valid!")
          } catch (e: GeneralSecurityException) {
            // ignored
          }
          return
        }
      }
    }
    throw IllegalArgumentException("$algorithm is not supported by the JCE!")
  }
}
