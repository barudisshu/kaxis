/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.auth

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

internal class PreSharedKeyIdentityTest {
  /**
   * Verifies that the constructor rejects a host name containing a colon character.
   */
  @Test
  fun testConstructorRejectsIllegalHostName() {
    assertThrows<IllegalArgumentException> { PreSharedKeyIdentity("illegal.host:name", "acme") }
  }

  /**
   * Verifies that two instances with the same identity but different virtual host names are not considered equal.
   */
  @Test
  fun testEqualsDetectsNonMatchingVirtualHost() {
    val idOne = PreSharedKeyIdentity("iot.kaxis.io", "device-1")
    val idTwo = PreSharedKeyIdentity("coap.kaxis.io", "device-1")
    assertNotEquals(idTwo, idOne)
    assertTrue(idOne.isScopedIdentity)
  }

  /**
   * Verifies that two instances with the same identity and virtual host are considered equal.
   */
  @Test
  fun testEqualsSucceeds() {
    val idOne = PreSharedKeyIdentity("iot.kaxis.io", "device-1")
    val idTwo = PreSharedKeyIdentity("iot.kaxis.io", "device-1")
    assertEquals(idOne, idTwo)
    assertTrue(idOne.isScopedIdentity)
  }

  /**
   * Verifies that two instances with the same identity but one with virtual host and one without are not considered equal.
   */
  @Test
  fun testEqualsFails() {
    val idOne = PreSharedKeyIdentity("device-1")
    val idTwo = PreSharedKeyIdentity(null, "device-1")
    assertNotEquals(idOne, idTwo)
    assertFalse(idOne.isScopedIdentity)
    assertTrue(idTwo.isScopedIdentity)
  }
}
