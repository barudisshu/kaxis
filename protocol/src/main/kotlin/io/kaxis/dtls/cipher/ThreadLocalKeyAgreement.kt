/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.cipher

import javax.crypto.KeyAgreement

/**
 * Thread local KeyAgreement. Uses [ThreadLocal] to cache calls to [KeyAgreement.getInstance].
 */
class ThreadLocalKeyAgreement(algorithm: String) :
  ThreadLocalCrypto<KeyAgreement>({ KeyAgreement.getInstance(algorithm) })
