/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.exception

/**
 * Constructs a new DTLS exception with the specified detail message and cause. **NOTE** that the detail message associated with `cause` is not automatically incorporated in this DTLS exception's detail message.
 * @param message the detail message (which is saved for later retrieval by the [Throwable.cause] method).
 * @param cause the cause (which is saved for later retrieval by the [Throwable.cause] method). (A `null` value is permitted, and indicates that the cause is nonexistent or unknown.)
 */
abstract class DtlsException(message: String? = null, cause: Throwable? = null) : RuntimeException(message, cause)
