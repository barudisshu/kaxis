/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.exception

/**
 * Value exception. Message contains the value and details about the failure.
 */
class ValueException(message: String? = null) : Exception(message)
