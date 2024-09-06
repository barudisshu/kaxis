/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
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
