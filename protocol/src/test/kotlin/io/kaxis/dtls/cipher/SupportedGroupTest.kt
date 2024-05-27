/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.cipher

import io.kaxis.JceProvider
import io.kaxis.util.Utility
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import java.security.GeneralSecurityException
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

internal class SupportedGroupTest {
  companion object {
    private const val LOOPS = 10

    @BeforeAll
    @JvmStatic
    fun init() {
      JceProvider.init()
    }
  }

  @Test
  fun testGetSupportedGroupFromPublicKey() {
    XECDHECryptography.SupportedGroup.getUsableGroups().forEach { group ->
      try {
        val ecdhe = XECDHECryptography(group)
        val publicKey = ecdhe.publicKey
        val groupFromPublicKey = XECDHECryptography.SupportedGroup.fromPublicKey(publicKey)
        assertEquals(group, groupFromPublicKey)
      } catch (e: GeneralSecurityException) {
        fail(e.message)
      }
    }
  }

  @Test
  fun testPublicKeyEncoding() {
    XECDHECryptography.SupportedGroup.getUsableGroups().forEach { group ->
      try {
        val ecdhe = XECDHECryptography(group)
        val point = ecdhe.encodedPoint
        val publicKey = group.decodedPoint(point)
        assertEquals(ecdhe.publicKey, publicKey)
      } catch (e: GeneralSecurityException) {
        fail(e.message)
      }
    }
  }

  @Test
  fun testGetUsableGroupsReturnsOnlyGroupsWithKnownDomainParams() {
    val length = XECDHECryptography.SupportedGroup.entries.size
    val usablegroups = XECDHECryptography.SupportedGroup.getUsableGroups()
    val preferredgroups = XECDHECryptography.SupportedGroup.getPreferredGroups()
    assertTrue(usablegroups.isNotEmpty())
    assertTrue(length >= usablegroups.size)
    assertTrue(preferredgroups.isNotEmpty())
    assertTrue(usablegroups.size >= preferredgroups.size)
    println("groups: $length, usable: ${usablegroups.size}, preferred: ${preferredgroups.size}")
  }

  /**
   * Mocking the key_exchange behaviors
   */
  @Test
  fun testDheKeyExchange() {
    XECDHECryptography.SupportedGroup.getUsableGroups().forEach { group ->
      for (loop in 0 until LOOPS) {
        try {
          val ecdhe1 = XECDHECryptography(group)
          val point1 = ecdhe1.encodedPoint
          assertNotNull(point1)
          val asn1 = ecdhe1.publicKey.encoded
          check(group, point1, asn1)

          val ecdhe2 = XECDHECryptography(group)
          val point2 = ecdhe2.encodedPoint
          assertNotNull(point2)
          val asn2 = ecdhe2.publicKey.encoded
          check(group, point2, asn2)

          val secret1 = ecdhe1.generateSecret(point2)
          assertNotNull(secret1)
          val secret2 = ecdhe2.generateSecret(point1)
          assertNotNull(secret2)
          assertEquals(secret2, secret1, "edhe failed!")
        } catch (e: Throwable) {
          fail("${group.name}: ${e.message}")
        }
      }
    }
  }

  private fun check(
    group: XECDHECryptography.SupportedGroup,
    point: ByteArray,
    asn1: ByteArray,
  ) {
    for (index in point.indices) {
      if (point[point.size - index - 1] != asn1[asn1.size - index - 1]) {
        val s1 = Utility.byteArray2Hex(asn1)
        var s2 = Utility.byteArray2Hex(point)
        requireNotNull(s1)
        requireNotNull(s2)
        if (s2.length < s1.length) {
          s2 = String.format("%${s1.length}s", s2)
        }
        println("ASN encoded '$s1'")
        println("DHE encoded '$s2'")
        fail<Unit>("DHE: failed to encoded point! ${group.name}, position: $index")
      }
    }
  }
}
