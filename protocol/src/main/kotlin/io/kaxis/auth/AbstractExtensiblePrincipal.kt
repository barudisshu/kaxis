/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
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
