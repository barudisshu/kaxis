/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.exception

import io.kaxis.dtls.message.AlertMessage

/**
 * The base exception class for all exceptions during a DTLS handshake.
 * @param message message
 * @param alert related alert
 * @param cause root cause
 */
class HandshakeException(
  val alert: AlertMessage,
  message: String?,
  cause: Throwable? = null,
) : Exception(message, cause)
