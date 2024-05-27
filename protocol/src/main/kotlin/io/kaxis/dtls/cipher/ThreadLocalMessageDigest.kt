/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.cipher

import java.security.MessageDigest

/**
 * Thread local MessageDigest. Uses [ThreadLocal] to cache calls to [MessageDigest.getInstance]
 */
class ThreadLocalMessageDigest(algorithm: String) :
  ThreadLocalCrypto<MessageDigest>({ MessageDigest.getInstance(algorithm) })
