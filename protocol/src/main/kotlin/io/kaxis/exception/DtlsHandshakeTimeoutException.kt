/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.exception

/**
 * Raised when a handshake flight timed-out.
 *
 * For more details on flight numbers, see [RFC 6347 §4.2.4. Timeout and Retransmission](https://tools.ietf.org/html/rfc6347#section-4.2.4)
 * @param flightNumber Number of the flight which timed-out.
 */
class DtlsHandshakeTimeoutException(message: String? = null, val flightNumber: Int) : DtlsException(message)
