/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.auth

import io.kaxis.util.Utility
import java.util.*

/**
 * A principal representing an authenticated peer's identity as used in a _pre-shared key_ handshake.
 */
class PreSharedKeyIdentity : AbstractExtensiblePrincipal<PreSharedKeyIdentity> {
  val isScopedIdentity: Boolean
  val virtualHost: String?
  val identity: String
  private val name: String

  /**
   * Creates a new instance for an identity.
   * @param identity the identity
   * @throws NullPointerException if the identity is `null`
   */
  constructor(identity: String?) : this(false, null, identity, null)

  /**
   * Creates a new instance for an identity scoped to a virtual host.
   * @param virtualHost The virtual host name that the identity is scoped to. The host name will be converted to lower case.
   * @param identity the identity.
   * @throws NullPointerException if the identity is `null`
   * @throws IllegalArgumentException if virtual host is not a valid host name s per [RFC 1123](https://tools.ietf.org/html/rfc1123).
   */
  constructor(virtualHost: String?, identity: String?) : this(true, virtualHost, identity, null)

  /**
   * Creates a new instance for an identity scoped to a virtual host.
   * @param sni enable scope to a virtual host
   * @param virtualHost The virtual host name that the identity is scoped to. The host name will be converted to lower case.
   * @param identity the identity.
   * @param additionalInformation Additional information for this principal.
   * @throws NullPointerException if the identity is `null`
   * @throws IllegalArgumentException if virtual host is not a valid host name s per [RFC 1123](https://tools.ietf.org/html/rfc1123).
   */
  constructor(
    sni: Boolean,
    virtualHost: String?,
    identity: String?,
    additionalInformation: AdditionalInfo?,
  ) : super(additionalInformation) {
    requireNotNull(identity) { "Identity must not be null" }
    isScopedIdentity = sni
    if (sni) {
      val b = StringBuilder()
      if (virtualHost == null) {
        this.virtualHost = null
      } else if (Utility.isValidHostName(virtualHost)) {
        this.virtualHost = virtualHost.lowercase()
        b.append(this.virtualHost)
      } else {
        throw IllegalArgumentException("virtual host is not a valid hostname")
      }
      b.append(":")
      b.append(identity)
      this.name = b.toString()
    } else {
      require(virtualHost == null) { "virtual host is not supported, if sni is disabled" }
      this.virtualHost = null
      this.name = identity
    }
    this.identity = identity
  }

  private constructor(
    scopedIdentity: Boolean,
    virtualHost: String?,
    identity: String,
    name: String,
    additionalInformation: AdditionalInfo?,
  ) : super(additionalInformation) {
    this.isScopedIdentity = scopedIdentity
    this.virtualHost = virtualHost
    this.identity = identity
    this.name = name
  }

  override fun amend(additionInfo: AdditionalInfo): PreSharedKeyIdentity {
    return PreSharedKeyIdentity(isScopedIdentity, virtualHost, identity, name, additionInfo)
  }

  override fun getName(): String = name

  override fun toString(): String {
    return if (isScopedIdentity) {
      "PreSharedKey Identity [virtual host: $virtualHost, identity: $identity]"
    } else {
      "PreSharedKey Identity [identity: $identity]"
    }
  }

  override fun hashCode(): Int {
    return name.hashCode()
  }

  override fun equals(other: Any?): Boolean {
    return if (this === other) {
      true
    } else if (other == null) {
      false
    } else if (other !is PreSharedKeyIdentity) {
      false
    } else {
      Objects.equals(name, other.name)
    }
  }
}
