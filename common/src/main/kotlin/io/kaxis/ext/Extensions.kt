/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.ext

/**
 * Add value to list, if not already contained.
 *
 * @param value value to add. Not added, if `null`.
 *
 * @return the provided list
 * @throws NullPointerException if list is `null`
 */
fun <T> MutableList<T>?.addIfAbsent(value: T?): MutableList<T> {
  requireNotNull(this) { "List mut not be null!" }
  if (value != null && !this.contains(value)) {
    this.add(value)
  }
  return this
}

/**
 * Add values to list, if not already contained.
 *
 * @param newValues values to add. `null` are not added.
 *
 * @return the provided list
 * @throws NullPointerException if list is `null`
 */
fun <T> MutableList<T>?.addIfAbsent(newValues: List<T>?): MutableList<T> {
  requireNotNull(this) { "List mut not be null!" }
  if (!newValues.isNullOrEmpty()) {
    newValues.forEach { value ->
      if (value != null && !this.contains(value)) {
        this.add(value)
      }
    }
  }
  return this
}
