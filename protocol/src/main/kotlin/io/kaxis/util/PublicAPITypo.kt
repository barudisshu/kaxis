/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.util

/**
 * Mark elements, which are part of the public API, but contain typos in their name.
 * @param fixedName the (future) name without typo.
 */
annotation class PublicAPITypo(val fixedName: String)
