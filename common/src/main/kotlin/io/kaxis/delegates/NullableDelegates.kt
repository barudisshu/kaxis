/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.delegates

import kotlin.properties.ReadOnlyProperty
import kotlin.reflect.KProperty

/**
 * No matter how, make sure [func] returns the [V?] Is always not null.
 */
class NullableDelegates<T, V>(val func: (T) -> V?) : ReadOnlyProperty<T, V> {
  private var value: V? = null

  override fun getValue(
    thisRef: T,
    property: KProperty<*>,
  ): V {
    if (value == null) {
      value = func(thisRef)
    }
    return value!!
  }
}
