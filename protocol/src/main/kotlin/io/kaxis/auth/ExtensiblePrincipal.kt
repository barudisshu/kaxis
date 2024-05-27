/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.auth

import java.security.Principal

/**
 * A Principal that can be extended with additional information.
 * @param T the type of the principal.
 */
interface ExtensiblePrincipal<out T : Principal> : Principal {
  /**
   * Creates a shallow copy of this principal which contains additional information.
   *
   * The additional information can be retrieved from the returned copy using the [extendedInfo] method.
   * @param additionInfo the additional information
   */
  fun amend(additionInfo: AdditionalInfo): T?

  /**
   * Gets additional information about this principal.
   * @return An unmodifiable map of additional information for this principal. The map will be empty if no additional information is available.
   */
  val extendedInfo: AdditionalInfo
}
