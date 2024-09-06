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
 * A base class for implementing [ExtensiblePrincipal]s.
 *
 */
abstract class AbstractExtensiblePrincipal<out T : ExtensiblePrincipal<T>> : ExtensiblePrincipal<T> {
  private val additionalInfo: AdditionalInfo

  /**
   * Creates a new principal with no additional information.
   */
  constructor() : this(null)

  /**
   * Creates a new principal with additional information.
   * @param additionalInformation The additional information.
   */
  constructor(additionalInformation: AdditionalInfo?) {
    if (additionalInformation == null) {
      this.additionalInfo = AdditionalInfo.empty()
    } else {
      this.additionalInfo = additionalInformation
    }
  }

  override val extendedInfo: AdditionalInfo
    get() = additionalInfo
}
