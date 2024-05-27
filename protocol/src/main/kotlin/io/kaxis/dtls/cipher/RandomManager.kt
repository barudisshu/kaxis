/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.cipher

import java.security.SecureRandom
import kotlin.random.Random

/**
 * Random manager. Uses [ThreadLocal] to cache calls to [SecureRandom] and [Random].
 */
object RandomManager {
  private val START = System.currentTimeMillis()

  private val THREAD_LOCAL_SECURE_RANDOM = ThreadLocal.withInitial { SecureRandom() }

  /**
   * Get thread local secure random.
   * @return thread local secure random
   */
  fun currentSecureRandom(): SecureRandom = THREAD_LOCAL_SECURE_RANDOM.get()

  private val THREAD_LOCAL_RANDOM = ThreadLocal.withInitial { Random(START + Thread.currentThread().id) }

  /**
   * Get thread local random.
   * @return thread local random
   */
  fun currentRandom(): Random = THREAD_LOCAL_RANDOM.get()
}
