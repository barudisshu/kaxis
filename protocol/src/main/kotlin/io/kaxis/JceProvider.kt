/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis

import io.kaxis.util.Utility
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher

/**
 * Algorithm names used by the JCE. Only cares about RSA, EC, AES, Using JCE default provider.
 * @since JDK >= 15 support Ed25591 and Ed448(v2).
 */
@Suppress("ktlint:standard:property-naming")
class JceProvider private constructor(
  private val rsa: Boolean,
  private val ec: Boolean,
  private val ed25519: Boolean,
  private val ed448: Boolean,
  private val strongEncryption: Boolean,
  private val ecdsaVulnerable: Boolean,
  private val providerVersion: String,
) {
  override fun hashCode(): Int {
    val prime = 31
    var result = 1
    result = prime * result + (if (ed25519) 41 else 37)
    result = prime * result + (if (ed448) 41 else 37)
    result = prime * result + (if (strongEncryption) 41 else 37)
    result = prime * result + (if (ecdsaVulnerable) 41 else 37)
    result = prime * result + (if (ec) 41 else 37)
    result = prime * result + (if (rsa) 41 else 37)
    result = prime * result + providerVersion.hashCode()
    return result
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other == null) return false
    if (other.javaClass != javaClass) return false
    val jceProvider = other as JceProvider
    if (ed25519 != jceProvider.ed25519) return false
    if (ed448 != jceProvider.ed448) return false
    if (strongEncryption != jceProvider.strongEncryption) return false
    if (ec != jceProvider.ec) return false
    if (rsa != jceProvider.rsa) return false
    if (providerVersion != jceProvider.providerVersion) return false
    return true
  }

  companion object {
    private val LOGGER: Logger = LoggerFactory.getLogger(JceProvider::class.java)

    /**
     * Key algorithm EC to be used by KeyFactory.
     */
    const val EC: String = "EC"

    /**
     * Key algorithm EC v2 (RFC 5958), not to be used by KeyFactory.
     */
    const val ECv2: String = "EC.v2"

    /**
     * Key algorithm RSA to be used by KeyFactory.
     */
    const val RSA: String = "RSA"

    /**
     * Key algorithm DSA to be used by KeyFactory.
     */
    const val DSA: String = "DSA"

    /**
     * Key algorithm DH to be used by KeyFactory.
     */
    const val DH: String = "DH"

    /**
     * Key algorithm EdDSA (RFC 8422).
     */
    const val EDDSA: String = "EdDSA"

    /**
     * Key algorithm ED25519 (RFC 8422).
     */
    const val ED25519: String = "Ed25519"

    /**
     * Key algorithm Ed25519.v2 (RFC 8410), not to be used by KeyFactory.
     */
    const val ED25519v2: String = "Ed25519.v2"

    /**
     * OID key algorithm ED25519 ([RFC 8410, 3. Curve25519 and Curve448 Algorithm Identifiers](https://datatracker.ietf.org/doc/html/rfc8410#section-3))
     */
    const val OID_ED25519: String = "OID.1.3.101.112"

    /**
     * Key algorithm ED448 (RFC 8422).
     */
    const val ED448: String = "Ed448"

    /**
     * Key algorithm Ed448 v2 (RFC 8410), not to be used by KeyFactory.
     */
    const val ED448v2: String = "Ed448.v2"

    /**
     * OID key algorithm ED448 ([RFC 8410, 3. Curve25519 and Curve448 Algorithm Identifiers](https://datatracker.ietf.org/doc/html/rfc8410#section-3)).
     */
    const val OID_ED448: String = "OID.1.3.101.113"

    /**
     * Key algorithm X25519 (RFC 8422).
     */
    const val X25519: String = "X25519"

    /**
     * Key algorithm X25519v2 (RFC 8410), not to be used by KeyFactory.
     */
    const val X25519v2: String = "X25519.v2"

    /**
     * OID key algorithm X25519 ([RFC 8410, 3. Curve25519 and Curve448 Algorithm Identifiers](https://datatracker.ietf.org/doc/html/rfc8410#section-3))
     */
    const val OID_X25519: String = "OID.1.3.101.110"

    /**
     * Key algorithm X448 (RFC 8422).
     */
    const val X448: String = "X448"

    /**
     * Key algorithm X448 v2 (RFC 8410), not to be used by KeyFactory.
     */
    const val X448v2: String = "X448.v2"

    /**
     * OID key algorithm X448 ([RFC 8410, 3. Curve25519 and Curve448 Algorithm Identifiers](https://datatracker.ietf.org/doc/html/rfc8410#section-3))
     */
    const val OID_X448: String = "OID.1.3.101.111"

    /**
     * Name of environment variable to specify, if the used JCE is tested for the ECDSA vulnerability [ECDSA vulnerability, CVE-2022-21449](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21449).
     *
     * The default is to test it. If the value of this environment variable is set to `false`, the test is suppressed and no additional checks for such signatures are done.
     */
    const val KAXIS_JCE_ECDSA_FIX: String = "KAXIS_JCE_ECDSA_FIX"

    /**
     * Alias algorithms for ED25519.
     */
    private val ED25519_ALIASES: Array<String> = arrayOf(ED25519, "1.3.101.112", OID_ED25519, EDDSA, ED25519v2)

    /**
     * Alias algorithms for Ed448.
     */
    private val ED448_ALIASES: Array<String> = arrayOf(ED448, "1.3.101.113", OID_ED448, EDDSA, ED448v2)

    /**
     * Table of algorithm aliases.
     */
    private val ALGORITHM_ALIASES: Array<Array<String>> =
      arrayOf(
        arrayOf(DH, "DiffieHellman"),
        arrayOf(EC, ECv2),
        ED25519_ALIASES,
        ED448_ALIASES,
        arrayOf(
          X25519,
          X25519v2,
          OID_X25519,
        ),
        arrayOf(X448, X448v2, OID_X448),
      )

    /**
     * Cipher name to check for the maximum allowed key length.
     * A key length of 256 bits or larger is considered as strong encryption.
     */
    private const val AES: String = "AES"

    /**
     * Ensure, the class is initialized.
     */
    @JvmStatic
    @Suppress("kotlin:S3776")
    fun init() {
      var found = false
      var provider: Provider? = null
      try {
        val factory = KeyFactory.getInstance(EDDSA)
        provider = factory.provider
        found = true
        LOGGER.trace("EdDSA from default jce {}", provider.name)
      } catch (e: NoSuchAlgorithmException) {
        LOGGER.warn("EdDSA not provided")
      }
      var ec = false
      var rsa = false
      var ecdsaVulnerable = false
      var aesPermission = "not supported"
      var aesMaxAllowedKeyLength = 0
      try {
        aesMaxAllowedKeyLength = Cipher.getMaxAllowedKeyLength(AES)
        aesPermission =
          if (aesMaxAllowedKeyLength == Integer.MAX_VALUE) {
            "not restricted"
          } else {
            "restricted to $aesMaxAllowedKeyLength bits key length"
          }
      } catch (ex: NoSuchAlgorithmException) {
        LOGGER.warn("AES not provided")
      }
      LOGGER.debug("AES: {}", aesPermission)
      try {
        KeyFactory.getInstance(RSA)
        rsa = true
      } catch (e: NoSuchAlgorithmException) {
        LOGGER.warn("RSA not provided")
      }
      LOGGER.debug("RSA: {}", rsa)
      try {
        KeyFactory.getInstance(EC)
        ec = true
      } catch (e: NoSuchAlgorithmException) {
        LOGGER.warn("EC not provided")
      }
      LOGGER.debug("EC: {}", ec)
      if (ec) {
        val ecdsaFix = Utility.getConfiguration(KAXIS_JCE_ECDSA_FIX)
        if (ecdsaFix == null || !ecdsaFix.equals("false", true)) {
          ecdsaVulnerable = true
          try {
            val signature = Signature.getInstance("SHA256withECDSA")
            val keyPairGenerator = KeyPairGenerator.getInstance("EC")
            keyPairGenerator.initialize(ECGenParameterSpec("secp256r1"))
            val keyPair = keyPairGenerator.generateKeyPair()
            // malicious signature
            val ghost = Utility.hex2ByteArray("3006020100020100")
            signature.initVerify(keyPair.public)
            signature.update(ghost)
            ecdsaVulnerable = signature.verify(ghost)
          } catch (e: Exception) {
            LOGGER.warn("ECDSA is vulnerable.")
          }
          LOGGER.debug("ECDSA {}vulnerable.", if (ecdsaVulnerable) "" else "not ")
        }
      }
      LOGGER.info("RSA: {}, EC: {}, AES: {}", rsa, ec, aesPermission)
      val version = provider?.versionStr ?: "n.a."
      var ed25519 = false
      var ed448 = false
      if (found) {
        try {
          KeyFactory.getInstance(ED25519)
          ed25519 = true
        } catch (e: NoSuchAlgorithmException) {
          LOGGER.warn("Ed25519 not provided!")
        }
        try {
          KeyFactory.getInstance(ED448)
          ed448 = true
        } catch (e: NoSuchAlgorithmException) {
          LOGGER.warn("Ed448 not provided!")
        }
        LOGGER.info("EdDSA supported by {}, Ed25519: {}, Ed448: {}", provider!!.name, ed25519, ed448)
      } else {
        provider = null
        LOGGER.info("EdDSA not supported!")
      }
      val newSupport = JceProvider(rsa, ec, ed25519, ed448, aesMaxAllowedKeyLength >= 256, ecdsaVulnerable, version)
      if (newSupport != features_) {
        this.features_ = newSupport
      }
      LOGGER.info("JCE setup: {}, ready.", provider)
      if (LOGGER.isDebugEnabled) {
        val providers = Security.getProviders()
        for (index in providers.indices) {
          provider = providers[index]
          LOGGER.debug("Security Provider [{}]: {}.", index, provider)
        }
        LOGGER.trace("JCE setup callstack: ", Throwable("JCE setup"))
      }
    }

    private var features_: JceProvider? = null

    /**
     * Information about JCE features.
     */
    private val features: JceProvider
      get() {
        if (features_ == null) {
          init()
        }
        return features_!!
      }

    /**
     * Checks, whether the JCE support strong encryption according to the installed JCE jurisdiction policy files.
     *
     * Checks for AES-256.
     */
    @JvmStatic
    fun hasStrongEncryption(): Boolean = features.strongEncryption

    /**
     * Check, if key algorithm is supported.
     * @param algorithm key algorithm
     * @return `true`, if supported, `false`, otherwise.
     */
    @JvmStatic
    fun isSupported(algorithm: String): Boolean {
      return when (algorithm) {
        EC -> features.ec
        RSA -> features.rsa
        else -> {
          val oid = getEdDsaStandardAlgorithmName(algorithm)
          when (oid) {
            OID_ED25519 -> features.ed25519
            OID_ED448 -> features.ed448
            EDDSA -> features.ed25519 || features.ed448
            else -> false
          }
        }
      }
    }

    /**
     * Get EdDSA standard algorithm name.
     * @param algorithm algorithm
     * @param def default algorithm
     * @return Either [OID_ED25519], [OID_ED448], [EDDSA], or the provided default
     */
    @JvmStatic
    fun getEdDsaStandardAlgorithmName(
      algorithm: String,
      def: String? = null,
    ): String? {
      return when {
        EDDSA.equals(algorithm, true) -> EDDSA
        Utility.containsIgnoreCase(ED25519_ALIASES, algorithm) -> OID_ED25519
        Utility.containsIgnoreCase(ED448_ALIASES, algorithm) -> OID_ED448
        else -> def
      }
    }

    /**
     * Check for equal key algorithm synonyms.
     * @param keyAlgorithm1 key algorithm 1
     * @param keyAlgorithm2 key algorithm 2
     * @return `true`, if the key algorithms are equal or synonyms, `false`, otherwise.
     */
    @JvmStatic
    fun equalKeyAlgorithmSynonyms(
      keyAlgorithm1: String?,
      keyAlgorithm2: String?,
    ): Boolean {
      if (keyAlgorithm1 != null && keyAlgorithm1 == keyAlgorithm2) {
        return true
      }
      for (alias in ALGORITHM_ALIASES) {
        if (Utility.containsIgnoreCase(alias, keyAlgorithm1) && Utility.containsIgnoreCase(alias, keyAlgorithm2)) {
          return true
        }
      }
      return false
    }

    /**
     * Get provider version.
     * @return provider version. "n.a.", if not available.
     * @see [Provider.versionStr]
     */
    @JvmStatic
    fun getProviderVersion(): String = features.providerVersion

    /**
     * Checks, if the JCE is affected by the ECDSA vulnerability. Some java JCE versions 15 to 18 fail to check the signature for 0 and n.
     * @return `true`, if the JCE has the ECDSA vulnerability, `false`, otherwise, Signature received signature.
     * @see [KAXIS_JCE_ECDSA_FIX]
     * @see [CVE-2022-21449](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21449)
     */
    @JvmStatic
    fun isEcdsaVulnerable(): Boolean = features.ecdsaVulnerable
  }
}
