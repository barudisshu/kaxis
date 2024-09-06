/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.cipher

import java.security.GeneralSecurityException

/**
 * Thread local crypto function. Uses [ThreadLocal] to cache calls to [ThreadLocalCrypto.Factory.getInstance].
 */
open class ThreadLocalCrypto<CryptoFunction> {
  val factory: Factory<CryptoFunction>?
  val exception: GeneralSecurityException?
  val threadLocalFunction: ThreadLocal<CryptoFunction>?

  /**
   * Check, if crypto function is supported by the java-vm.
   * @return `true`, if crypto function is supported by the java-vm.
   */
  val isSupported: Boolean
    get() = exception == null

  /**
   * Get the failure of the initial try to instantiate the crypto function for the provided factory.
   * @return failure, or `null`, if no failure occurred.
   */
  val cause: GeneralSecurityException?
    get() = exception

  /**
   * Get "thread local" instance of crypto function.
   * @return thread local function, or `null`, if crypto function is not supported by the java-vm.
   */
  fun current(): CryptoFunction? {
    if (!isSupported) {
      return null
    }
    var function = threadLocalFunction?.get()
    if (function == null) {
      try {
        function = factory?.getInstance()
        threadLocalFunction?.set(function)
      } catch (e: GeneralSecurityException) {
        // NOSONAR
      }
    }
    return function
  }

  /**
   * Get "thread local" instance of crypto function.
   * @return thread local crypto function.
   * @throws GeneralSecurityException if crypto function is not supported by the java-vm.
   */
  @Throws(GeneralSecurityException::class)
  fun currentWithCause(): CryptoFunction? {
    return if (exception != null) {
      throw exception
    } else {
      current()
    }
  }

  /**
   * Create thread local crypto function. Try to instance the crypto function for the provided factory. Failures
   * may be accessed by [cause]. Use [isSupported] to check, if the java-vm supports the crypto function.
   *
   * @param factory factory to create instances of the crypto function.
   * @see ThreadLocalCipher
   * @see ThreadLocalMac
   * @see ThreadLocalMessageDigest
   */
  constructor(factory: Factory<CryptoFunction>) {
    var exception: GeneralSecurityException? = null
    var supportedFactory: Factory<CryptoFunction>? = null
    var threadLocalCipher: ThreadLocal<CryptoFunction>? = null

    try {
      val function = factory.getInstance()
      if (function != null) {
        supportedFactory = factory
        threadLocalCipher = ThreadLocal()
        threadLocalCipher.set(function)
      } else {
        exception = GeneralSecurityException(factory::class.simpleName + " not supported!")
      }
    } catch (e: GeneralSecurityException) {
      exception = e
    }

    this.threadLocalFunction = threadLocalCipher
    this.factory = supportedFactory
    this.exception = exception
  }

  /**
   * Factory to create instances of crypto functions.
   */
  fun interface Factory<CryptoFunction> {
    /**
     * Create instance of crypto function.
     *
     * @return crypto function, or `null`, if not supported
     * @throws GeneralSecurityException if not supported.
     */
    @Throws(GeneralSecurityException::class)
    fun getInstance(): CryptoFunction?
  }
}
