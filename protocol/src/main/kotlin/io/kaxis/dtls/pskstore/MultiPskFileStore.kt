/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.pskstore

import io.kaxis.Bytes
import io.kaxis.dtls.ConnectionId
import io.kaxis.dtls.HandshakeResultHandler
import io.kaxis.dtls.PskPublicInformation
import io.kaxis.dtls.ServerNames
import io.kaxis.result.PskSecretResult
import io.kaxis.util.EncryptedStreamUtil
import io.kaxis.util.SecretUtil
import io.kaxis.util.Utility
import org.slf4j.LoggerFactory
import java.io.*
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.util.*
import java.util.concurrent.locks.ReentrantReadWriteLock
import javax.crypto.SecretKey
import javax.security.auth.Destroyable

/**
 * File based [AdvancedPskStore] implementation supporting multiple peers.
 *
 * Lines in format:
 *
 * ```
 * identity = secret - key(base64)
 * ```
 *
 * or
 *
 * ```
 * identity = ":0x" secret-key (hex)
 * ```
 *
 * Example:
 *
 * ```
 * Client_identity=c2VjcmV0UFNL
 * imei351358811124772=:0x736573616D65
 * ```
 * ```
 * Base 64 "c2VjcmV0UFNL" := "secretPSK"
 * Hex "736573616D65" := "sesame"
 * ```
 */
open class MultiPskFileStore : AdvancedPskStore, Destroyable {
  companion object {
    private val LOGGER = LoggerFactory.getLogger(MultiPskFileStore::class.java)

    private class Credentials : Destroyable {
      private val lock = ReentrantReadWriteLock()

      /**
       * List of identities.
       */
      private val identities = arrayListOf<PskPublicInformation?>()

      /**
       * Map of identities and keys.
       */
      private val keys = hashMapOf<PskPublicInformation, SecretKey?>()

      /**
       * `true` if credentials are destroyed.
       */
      @Volatile
      private var destroyed: Boolean = false

      /**
       * Add entry. New entries are appended to the index. Updated entries do not change their
       * index position.
       *
       * @param id PSK identity
       * @param key PSK secret
       */
      fun add(
        id: PskPublicInformation,
        key: SecretKey?,
      ) {
        lock.writeLock().lock()
        try {
          if (keys.putIfAbsent(id, key) == null) {
            identities.add(id)
          }
        } finally {
          lock.writeLock().unlock()
        }
      }

      /**
       * Remove entry.
       *
       * @param id PSK identity
       */
      fun remove(id: PskPublicInformation) {
        lock.writeLock().lock()
        try {
          val key = keys.remove(id)
          if (key != null) {
            SecretUtil.destroy(key)
            identities.remove(id)
          }
        } finally {
          lock.writeLock().unlock()
        }
      }

      /**
       * Remove entry by index. The index is based on the order of [add] new entries.
       *
       * @param index index of entry.
       * @throws IndexOutOfBoundsException if index is out of bounds
       */
      fun remove(index: Int) {
        lock.writeLock().lock()
        try {
          val id = identities.removeAt(index)
          if (id != null) {
            val key = keys.remove(id)
            if (key != null) {
              SecretUtil.destroy(key)
            }
          }
        } finally {
          lock.writeLock().unlock()
        }
      }

      /**
       * Get PSK secret by PSK identity.
       *
       * @param id PSK identity
       * @return PSK secret, `null`, if not available.
       */
      fun getSecret(id: PskPublicInformation): SecretKey? {
        val key: SecretKey?
        lock.readLock().lock()
        try {
          key = keys[id]
        } finally {
          lock.readLock().unlock()
        }
        return SecretUtil.create(key)
      }

      /**
       * Get PSK secret by index. The index is based on the order of [add] new entries.
       *
       * @param index index of entry.
       * @return PSK secret
       * @throws IndexOutOfBoundsException if index is out of bounds
       */
      fun getSecret(index: Int): SecretKey? {
        lock.readLock().lock()
        try {
          val info = identities[index]
          if (info != null) {
            return getSecret(info)
          }
          return null
        } finally {
          lock.readLock().unlock()
        }
      }

      /**
       * Get identity by index. The index is based on the order of [add] new entries.
       *
       * @param index index of identity
       * @return identity as string
       * @throws IndexOutOfBoundsException if index is out of bounds
       */
      fun getIdentity(index: Int): String? {
        val info: PskPublicInformation?
        lock.readLock().lock()
        try {
          info = identities[index]
        } finally {
          lock.readLock().unlock()
        }
        if (info != null) {
          return info.publicInfoAsString
        }
        return null
      }

      /**
       * Number of entries.
       * @return number of entries
       */
      fun size(): Int {
        lock.readLock().lock()
        try {
          return identities.size
        } finally {
          lock.readLock().unlock()
        }
      }

      /**
       * Lines in format:
       * ```
       * identity = secret - key(base64)
       * ```
       *
       * @param writer writer to save PSK credentials
       * @throws IOException if an I/O error occurred
       */
      @Throws(IOException::class)
      fun savePskCredentials(writer: Writer) {
        identities.forEach { identity ->
          if (identity != null) {
            val secretKey = keys[identity]
            if (secretKey != null) {
              val key = secretKey.encoded
              val base64 = Utility.byteArrayToBase64CharArray(key)
              Bytes.clear(key)
              writer.write(identity.publicInfoAsString)
              writer.write("=")
              writer.write(base64)
              writer.write(Utility.LINE_SEPARATOR)
              Arrays.fill(base64, '.')
            }
          }
        }
      }

      /**
       * Load PSK credentials store. Lines in format:
       * ```
       * identity = secret - key(base64)
       * ```
       * or
       * ```
       * identity = ":0x" secret-key (hex)
       * ```
       * The identity must not contain a `=` !
       *
       * The psk credentials store keeps the order of the credentials in the file.
       * Index `0` will contain the credential of the first line.
       * @param reader reader for credentials store.
       * @throws IOException if an I/O error occurred
       */
      @Throws(IOException::class)
      fun loadPskCredentials(reader: Reader) {
        val lineReader = BufferedReader(reader)
        try {
          var lineNumber = 0
          var errors = 0
          var comments = 0
          var line: String
          // readLine() reads the secret into a String,
          // what may be considered to be a weak practice.
          while (lineReader.readLine().also { line = it } != null) {
            ++lineNumber
            try {
              if (line.isNotEmpty() && !line.startsWith("#")) {
                val entry = line.split("=".toRegex(), 2)
                if (entry.size == 2) {
                  val secretBytes =
                    if (entry[1].startsWith(":0x")) {
                      Utility.hex2ByteArray(entry[1].substring(3))
                    } else {
                      Utility.base64ToByteArray(entry[1])
                    }
                  if (secretBytes == null || secretBytes.isEmpty()) {
                    LOGGER.warn("{}: '{}' invalid base64 secret in psk-line!", lineNumber, line)
                    ++errors
                    continue
                  }
                  val key = SecretUtil.create(secretBytes, "PSK")
                  Bytes.clear(secretBytes)
                  val id = PskPublicInformation(entry[0])
                  add(id, key)
                } else {
                  ++errors
                  LOGGER.warn("{}: '{}' invalid psk-line entries!", lineNumber, line)
                }
              } else {
                ++comments
              }
            } catch (ex: IllegalArgumentException) {
              ++errors
              LOGGER.warn("{}: '{}' invalid psk-line!", lineNumber, line, ex)
            }
          }
          if (size() == 0 && errors > 0 && lineNumber == comments + errors) {
            LOGGER.warn("read psk-store, only errors, wrong password?")
            SecretUtil.destroy(this)
          }
        } catch (e: IOException) {
          if (e.cause is GeneralSecurityException) {
            LOGGER.warn("read psk-store, wrong password?", e)
            SecretUtil.destroy(this)
          } else {
            throw e
          }
        } finally {
          try {
            lineReader.close()
          } catch (e: IOException) {
            // NO SONAR
          }
        }
        LOGGER.info("read {} PSK credentials.", size())
      }

      override fun destroy() {
        lock.writeLock().lock()
        try {
          identities.clear()
          keys.values.forEach { credentials ->
            SecretUtil.destroy(credentials)
          }
          keys.clear()
          destroyed = true
        } finally {
          lock.writeLock().unlock()
        }
      }

      override fun isDestroyed(): Boolean {
        return destroyed
      }
    }
  }

  /**
   * Encryption utility for encrypted psk stores.
   */
  private val encryptionUtility = EncryptedStreamUtil()

  @Volatile
  private var credentials: Credentials = Credentials()

  /**
   * `true` if psk store is destroyed.
   */
  @Volatile
  private var destroyed: Boolean = false

  /**
   * Seed of last loaded file.
   *
   * The seed is a random header to ensure that the encrypted file will be different,
   * even if the same credentials are contained. Used to detect changes in encrypted file.
   */
  var seed: ByteArray? = null

  /**
   * Get write cipher specification.
   * @return cipher specification (algorithm + key size). e.g. "AES/GCM/128".
   */
  val writerCipher: String
    get() = encryptionUtility.writeCipher

  /**
   * Get read cipher specification.
   * @return cipher specification (algorithm + key size). e.g. "AES/GCM/128". `null`, if empty
   */
  val readCipher: String?
    get() = encryptionUtility.readCipher

  /**
   * Set cipher to default cipher.
   */
  fun setDefaultWriteCipher() = encryptionUtility.setDefaultWriteCipher()

  /**
   * Set algorithm and key size.
   * @param cipherAlgorithm cipher algorithm
   * @param keySizeBits key size in bits
   * @throws IllegalArgumentException if cipher and key size is not supported
   */
  fun setWriteCipher(
    cipherAlgorithm: String?,
    keySizeBits: Int,
  ) = encryptionUtility.setWriteCipher(cipherAlgorithm, keySizeBits)

  /**
   * Set algorithm and key size.
   * @param spec cipher specification (algorithm + key size). e.g. "AES/GCM/128".
   * @throws IllegalArgumentException if cipher and key size is not supported
   */
  fun setWriteCipher(spec: String?) = encryptionUtility.setWriteCipher(spec)

  /**
   * Clear seed to force loading. The store keeps the "seed" of encrypted files
   * in order to prevent reloading that same file. To force loading the file, clear
   * the "seed".
   */
  fun clearSeed() {
    this.seed = null
  }

  /**
   * Load PSK credentials store.
   *
   * @param file filename of credentials store.
   * @return the file based PSK store for chaining
   */
  fun loadPskCredentials(file: String): MultiPskFileStore {
    FileInputStream(file).use { input ->
      InputStreamReader(input, StandardCharsets.UTF_8).use { reader ->
        loadPskCredentials(reader)
      }
    }
    return this
  }

  /**
   * Load PSK credentials store.
   * @param input input stream.
   * @return the file based PSK store for chaining
   */
  fun loadPskCredentials(input: InputStream): MultiPskFileStore {
    InputStreamReader(input, StandardCharsets.UTF_8).use { reader ->
      loadPskCredentials(reader)
    }
    return this
  }

  /**
   * Load encrypted PSK credentials store.
   * @param file filename of credentials store
   * @param password password of credentials store
   * @return the file based PSK store for chaining
   */
  fun loadPskCredentials(
    file: String,
    password: SecretKey,
  ): MultiPskFileStore {
    FileInputStream(file).use { input ->
      loadPskCredentials(input, password)
    }
    return this
  }

  /**
   * Load encrypted PSK credentials store.
   *
   * @param input input stream of credentials store.
   * @param password password of credentials store.
   * @return the file based PSK store for chaining
   */
  fun loadPskCredentials(
    input: InputStream,
    password: SecretKey,
  ): MultiPskFileStore {
    val seed = encryptionUtility.readSeed(input)
    if (this.seed == null && !this.seed.contentEquals(seed)) {
      encryptionUtility.prepare(seed, input, password).use { inEncrypted ->
        loadPskCredentials(inEncrypted)
        this.seed = seed
      }
    } else {
      LOGGER.debug("Encrypted PSK store no changed seed.")
    }
    return this
  }

  /**
   * Load PSK credentials store.
   *
   * Lines in format:
   * ```
   * identity = secret - key(base64)
   * ```
   * or
   * ```
   * identity = ":0x" secret-key (hex)
   * ```
   *
   * The identity must not contains a `=` ! The psk credentials store keeps the order
   * of the credentials in the file. Index `0` will contain the credential of the first line.
   * @param reader reader for credentials store.
   * @return the file based PSK store for chaining
   * @throws IOException if an I/O error occurred
   */
  @Throws(IOException::class)
  fun loadPskCredentials(reader: Reader): MultiPskFileStore {
    val newCredentials = Credentials()
    newCredentials.loadPskCredentials(reader)
    if (newCredentials.isDestroyed) {
      if (credentials.size() == 0) {
        destroyed = true
      }
    } else {
      credentials = newCredentials
      this.seed = null
    }
    return this
  }

  /**
   * Save PSK credentials store.
   * @param file filename of credentials store.
   * @return the file based PSK store for chaining
   */
  fun savePskCredentials(file: String): MultiPskFileStore {
    FileOutputStream(file).use { out ->
      OutputStreamWriter(out, StandardCharsets.UTF_8).use { writer ->
        savePskCredentials(writer)
      }
    }
    return this
  }

  /**
   * Save PSK credenials store.
   * @param out output stream.
   * @return the file based PSK store for chaining
   */
  fun savePskCredentials(out: OutputStream): MultiPskFileStore {
    OutputStreamWriter(out, StandardCharsets.UTF_8).use { writer ->
      savePskCredentials(writer)
    }
    return this
  }

  /**
   * Save encrypted PSK credentials store.
   * @param file filename of credentials store.
   * @param password password of credentials store.
   * @return the file based PSK store for chaining
   */
  fun savePskCredentials(
    file: String,
    password: SecretKey,
  ): MultiPskFileStore {
    FileOutputStream(file).use { out ->
      savePskCredentials(out)
    }
    return this
  }

  /**
   * Save encrypted PSK credentials store.
   * @param out output stream to save credentials store.
   * @param password password to credentials store.
   * @return the file based PSK store for chaining
   */
  fun savePskCredentials(
    out: OutputStream,
    password: SecretKey,
  ): MultiPskFileStore {
    encryptionUtility.prepare(seed, out, password).use { outEncrypted ->
      savePskCredentials(outEncrypted)
    }
    return this
  }

  /**
   * Save PSK credentials store. Lines in format:
   * ```
   * identity = secret - key(base64)
   * ```
   *
   * @param writer writer to save PSK credentials
   * @return the file based PSK store for chaining
   * @throws IOException if an I/O error occurred
   */
  fun savePskCredentials(writer: Writer): MultiPskFileStore {
    credentials.savePskCredentials(writer)
    return this
  }

  /**
   * Add identity and secret.
   * @param identity identity
   * @param secret secret
   * @return the file based PSK store for chaining
   * @throws IllegalArgumentException if identity contains a `'='`.
   */
  fun addKey(
    identity: PskPublicInformation,
    secret: SecretKey,
  ): MultiPskFileStore {
    require(identity.publicInfoAsString.indexOf('=') < 0) { "Identity must not contain '='!" }
    credentials.add(identity, SecretUtil.create(secret))
    return this
  }

  /**
   * Add identity and secret.
   * @param identity identity
   * @param secret secret
   * @return the file based PSK store for chaining
   * @throws IllegalArgumentException if identity contains a `'='`.
   */
  fun addKey(
    identity: String,
    secret: SecretKey,
  ): MultiPskFileStore {
    return addKey(PskPublicInformation(identity), secret)
  }

  /**
   * Remove identity and secret.
   * @param identity identity
   * @return the file based PSK store for chaining
   */
  fun removeKey(identity: PskPublicInformation): MultiPskFileStore {
    credentials.remove(identity)
    return this
  }

  /**
   * Remove identity and secret.
   * @param index index of key
   * @return the file based PSK store for chaining
   * @throws IndexOutOfBoundsException if provided index is out of bounds
   */
  fun removeKey(index: Int): MultiPskFileStore {
    credentials.remove(index)
    return this
  }

  /**
   * Remove identity and secret.
   * @param identity identity
   * @return the file based PSK store for chaining
   */
  fun removeKey(identity: String?): MultiPskFileStore {
    return removeKey(PskPublicInformation(identity))
  }

  /**
   * Get identity.
   *
   * @param index index of identity.
   * @return identity at provided index
   * @throws IndexOutOfBoundsException if provided index is out of bounds
   */
  fun getIdentity(index: Int): String? = credentials.getIdentity(index)

  /**
   * Get secret key.
   * @param index index of key
   * @return secret key at provided index
   * @throws IndexOutOfBoundsException if provided index is out of bounds
   */
  fun getSecret(index: Int): SecretKey? = credentials.getSecret(index)

  /**
   * Get secret key.
   * @param identity identity
   * @return secret key for identity. `null` if not available.
   */
  fun getSecret(identity: String?): SecretKey? = credentials.getSecret(PskPublicInformation(identity))

  /**
   * Get secret key.
   * @param identity identity
   * @return secret key for identity. `null` if not available.
   */
  fun getSecret(identity: PskPublicInformation): SecretKey? = credentials.getSecret(identity)

  fun size(): Int = credentials.size()

  override fun destroy() {
    credentials.destroy()
    destroyed = true
  }

  override fun isDestroyed(): Boolean {
    return destroyed
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
    return PskSecretResult(cid, identity, credentials.getSecret(identity))
  }

  override fun getIdentity(
    peerAddress: InetSocketAddress?,
    virtualHost: ServerNames?,
  ): PskPublicInformation? {
    // not intended for clients
    return null
  }

  override fun setResultHandler(resultHandler: HandshakeResultHandler) {
    // empty implementation
  }
}
