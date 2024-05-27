/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.exception

import java.io.IOException

/**
 * Value exception. Message contains the value and details about the failure.
 */
class StreamOverflowException(message: String? = null) : IOException(message)
