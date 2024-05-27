/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.cipher

import javax.crypto.Mac

/**
 * Thread local mac. Uses [ThreadLocal] to cache calls to [Mac.getInstance]
 */
class ThreadLocalMac(algorithm: String) : ThreadLocalCrypto<Mac>({ Mac.getInstance(algorithm) })
