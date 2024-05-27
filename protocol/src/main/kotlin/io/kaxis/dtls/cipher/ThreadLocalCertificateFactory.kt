/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.cipher

import java.security.cert.CertificateFactory

/**
 * Thread local CertificateFactory. Uses [ThreadLocal] to cache calls to [CertificateFactory.getInstance].
 */
class ThreadLocalCertificateFactory(algorithm: String) :
  ThreadLocalCrypto<CertificateFactory>({ CertificateFactory.getInstance(algorithm) })
