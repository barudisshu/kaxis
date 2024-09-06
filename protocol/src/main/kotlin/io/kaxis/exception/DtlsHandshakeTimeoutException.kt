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

/**
 * Raised when a handshake flight timed-out.
 *
 * For more details on flight numbers, see [RFC 6347 §4.2.4. Timeout and Retransmission](https://tools.ietf.org/html/rfc6347#section-4.2.4)
 * @param flightNumber Number of the flight which timed-out.
 */
class DtlsHandshakeTimeoutException(message: String? = null, val flightNumber: Int) : DtlsException(message)
