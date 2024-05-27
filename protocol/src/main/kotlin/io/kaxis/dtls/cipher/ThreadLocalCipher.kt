/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.cipher

import javax.crypto.Cipher

/**
 * Thread local cipher. Uses [ThreadLocal] to cache calls to [Cipher.getInstance]
 */
class ThreadLocalCipher(transformation: String) : ThreadLocalCrypto<Cipher>({ Cipher.getInstance(transformation) })
