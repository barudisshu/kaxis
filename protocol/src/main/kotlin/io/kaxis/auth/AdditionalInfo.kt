/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.auth

/**
 * an unmodifiable wrapper around additional information about an authenticated peer.
 */
class AdditionalInfo private constructor(additionalInfo: Map<String, Any>?) {
  companion object {
    private val EMPTY_MAP = hashMapOf<String, Any>()

    /**
     * Creates empty additional information.
     * @return the info.
     */
    fun empty(): AdditionalInfo = AdditionalInfo(null)
  }

  private val info: Map<String, Any> =
    if (additionalInfo == null) {
      EMPTY_MAP
    } else {
      HashMap(additionalInfo)
    }

  /**
   * Get info for a key.
   * @param key the key to get the value for.
   * @param type the expected type of the value.
   * @return the value or `null` if no value of the given type is registered for the key.
   */
  operator fun <T> get(
    key: String,
    type: Class<T>,
  ): T? {
    val value = info[key]
    return if (type.isInstance(value)) {
      type.cast(value)
    } else {
      null
    }
  }
}
