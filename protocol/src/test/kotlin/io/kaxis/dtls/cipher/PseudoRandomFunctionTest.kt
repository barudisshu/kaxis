/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.cipher

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

internal class PseudoRandomFunctionTest {
  companion object {
    const val ALGORITHM_HMAC_SHA256 = "HmacSHA256"
  }

  private lateinit var hmac: Mac

  @BeforeEach
  fun setUp() {
    hmac = Mac.getInstance("HmacSHA256")
  }

  @Test
  fun testDoPrfProducesDataOfCorrectLength() {
    val secret = SecretKeySpec("secret".toByteArray(), "MAC")
    val seed = "seed".toByteArray()
    var data = PseudoRandomFunction.doPRF(hmac, secret, PseudoRandomFunction.Label.MASTER_SECRET_LABEL, seed)
    assertEquals(PseudoRandomFunction.Label.MASTER_SECRET_LABEL.length, data.size)
    data = PseudoRandomFunction.doPRF(hmac, secret, PseudoRandomFunction.Label.KEY_EXPANSION_LABEL, seed)
    assertEquals(PseudoRandomFunction.Label.KEY_EXPANSION_LABEL.length, data.size)
    data = PseudoRandomFunction.doPRF(hmac, secret, PseudoRandomFunction.Label.CLIENT_FINISHED_LABEL, seed)
    assertEquals(PseudoRandomFunction.Label.CLIENT_FINISHED_LABEL.length, data.size)
    data = PseudoRandomFunction.doPRF(hmac, secret, PseudoRandomFunction.Label.SERVER_FINISHED_LABEL, seed)
    assertEquals(PseudoRandomFunction.Label.SERVER_FINISHED_LABEL.length, data.size)
  }

  @Test
  fun testExpansionProducesCorrectData() {
    val seed =
      byteArrayOf(
        0xa0.toByte(),
        0xba.toByte(),
        0x9f.toByte(),
        0x93.toByte(),
        0x6c.toByte(),
        0xda.toByte(),
        0x31.toByte(),
        0x18.toByte(),
        0x27.toByte(),
        0xa6.toByte(),
        0xf7.toByte(),
        0x96.toByte(),
        0xff.toByte(),
        0xd5.toByte(),
        0x19.toByte(),
        0x8c.toByte(),
      )
    val secret =
      byteArrayOf(
        0x9b.toByte(),
        0xbe.toByte(),
        0x43.toByte(),
        0x6b.toByte(),
        0xa9.toByte(),
        0x40.toByte(),
        0xf0.toByte(),
        0x17.toByte(),
        0xb1.toByte(),
        0x76.toByte(),
        0x52.toByte(),
        0x84.toByte(),
        0x9a.toByte(),
        0x71.toByte(),
        0xdb.toByte(),
        0x35.toByte(),
      )
    val label = "test label".toByteArray()
    val expectedOutput =
      byteArrayOf(
        0xe3.toByte(),
        0xf2.toByte(),
        0x29.toByte(),
        0xba.toByte(),
        0x72.toByte(),
        0x7b.toByte(),
        0xe1.toByte(),
        0x7b.toByte(),
        0x8d.toByte(),
        0x12.toByte(),
        0x26.toByte(),
        0x20.toByte(),
        0x55.toByte(),
        0x7c.toByte(),
        0xd4.toByte(),
        0x53.toByte(),
        0xc2.toByte(),
        0xaa.toByte(),
        0xb2.toByte(),
        0x1d.toByte(),
        0x07.toByte(),
        0xc3.toByte(),
        0xd4.toByte(),
        0x95.toByte(),
        0x32.toByte(),
        0x9b.toByte(),
        0x52.toByte(),
        0xd4.toByte(),
        0xe6.toByte(),
        0x1e.toByte(),
        0xdb.toByte(),
        0x5a.toByte(),
        0x6b.toByte(),
        0x30.toByte(),
        0x17.toByte(),
        0x91.toByte(),
        0xe9.toByte(),
        0x0d.toByte(),
        0x35.toByte(),
        0xc9.toByte(),
        0xc9.toByte(),
        0xa4.toByte(),
        0x6b.toByte(),
        0x4e.toByte(),
        0x14.toByte(),
        0xba.toByte(),
        0xf9.toByte(),
        0xaf.toByte(),
        0x0f.toByte(),
        0xa0.toByte(),
        0x22.toByte(),
        0xf7.toByte(),
        0x07.toByte(),
        0x7d.toByte(),
        0xef.toByte(),
        0x17.toByte(),
        0xab.toByte(),
        0xfd.toByte(),
        0x37.toByte(),
        0x97.toByte(),
        0xc0.toByte(),
        0x56.toByte(),
        0x4b.toByte(),
        0xab.toByte(),
        0x4f.toByte(),
        0xbc.toByte(),
        0x91.toByte(),
        0x66.toByte(),
        0x6e.toByte(),
        0x9d.toByte(),
        0xef.toByte(),
        0x9b.toByte(),
        0x97.toByte(),
        0xfc.toByte(),
        0xe3.toByte(),
        0x4f.toByte(),
        0x79.toByte(),
        0x67.toByte(),
        0x89.toByte(),
        0xba.toByte(),
        0xa4.toByte(),
        0x80.toByte(),
        0x82.toByte(),
        0xd1.toByte(),
        0x22.toByte(),
        0xee.toByte(),
        0x42.toByte(),
        0xc5.toByte(),
        0xa7.toByte(),
        0x2e.toByte(),
        0x5a.toByte(),
        0x51.toByte(),
        0x10.toByte(),
        0xff.toByte(),
        0xf7.toByte(),
        0x01.toByte(),
        0x87.toByte(),
        0x34.toByte(),
        0x7b.toByte(),
        0x66.toByte(),
      )
    val data = PseudoRandomFunction.doPRF(hmac, SecretKeySpec(secret, "MAC"), label, seed, expectedOutput.size)
    assertArrayEquals(expectedOutput, data)
  }
}
