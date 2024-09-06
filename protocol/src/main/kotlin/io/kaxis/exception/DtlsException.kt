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
 * Constructs a new DTLS exception with the specified detail message and cause. **NOTE** that the detail message associated with `cause` is not automatically incorporated in this DTLS exception's detail message.
 * @param message the detail message (which is saved for later retrieval by the [Throwable.cause] method).
 * @param cause the cause (which is saved for later retrieval by the [Throwable.cause] method). (A `null` value is permitted, and indicates that the cause is nonexistent or unknown.)
 */
abstract class DtlsException(message: String? = null, cause: Throwable? = null) : RuntimeException(message, cause)
