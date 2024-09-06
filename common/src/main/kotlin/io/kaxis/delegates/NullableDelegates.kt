/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
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
