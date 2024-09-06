/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.pskstore

import io.kaxis.result.PskSecretResult
import io.kaxis.util.SecretUtil
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import javax.crypto.SecretKey
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

internal class MultiPskFileStoreTest {
  companion object {
    /**
     * ```
     * me=secret, you=public, it=hex.
     * ```
     */
    private val DATA =
      """
      |me=c2VjcmV0
      |you=cHVibGlj
      |it=:0x686578
      """.trimMargin().toByteArray()

    private val DATA_STRICT_BASE64 =
      """
      |me=c2VjcmV0
      |you=cHVibGlj
      |it=aGV4
      """.trimMargin().toByteArray()
  }

  private lateinit var store: MultiPskFileStore
  private lateinit var secret: SecretKey

  @BeforeEach
  fun setUp() {
    store = MultiPskFileStore()
    secret = SecretUtil.create("secure".toByteArray(), "PW")
  }

  @AfterEach
  fun tearDown() {
    store.destroy()
    SecretUtil.destroy(secret)
  }

  @Test
  fun testLoadPlainPskStore() {
    store.loadPskCredentials(ByteArrayInputStream(DATA))
    assertEquals(3, store.size())

    var expected = SecretUtil.create("secret".toByteArray(), PskSecretResult.ALGORITHM_PSK)
    var key = store.getSecret("me")
    assertEquals(expected, key)
    SecretUtil.destroy(key)

    key = store.getSecret(0)
    assertEquals(expected, key)
    SecretUtil.destroy(key)
    SecretUtil.destroy(expected)

    expected = SecretUtil.create("public".toByteArray(), PskSecretResult.ALGORITHM_PSK)
    key = store.getSecret("you")
    assertEquals(expected, key)
    SecretUtil.destroy(key)

    key = store.getSecret(1)
    assertEquals(expected, key)
    SecretUtil.destroy(key)
    SecretUtil.destroy(expected)

    expected = SecretUtil.create("hex".toByteArray(), PskSecretResult.ALGORITHM_PSK)
    key = store.getSecret("it")
    assertEquals(expected, key)
    SecretUtil.destroy(key)

    key = store.getSecret(2)
    assertEquals(expected, key)
    SecretUtil.destroy(key)
    SecretUtil.destroy(expected)
  }

  @Test
  fun testSavePlainPskStore() {
    store.loadPskCredentials(ByteArrayInputStream(DATA))
    assertEquals(3, store.size())

    val out = ByteArrayOutputStream()
    store.savePskCredentials(out, secret)
    val encrypted = out.toByteArray()

    assertNotEquals(DATA, encrypted)
    val store2 = MultiPskFileStore()
    store2.loadPskCredentials(ByteArrayInputStream(encrypted), secret)
    assertEquals(store.size(), store2.size())

    for (index in 0 until store.size()) {
      assertEquals(store.getIdentity(index), store2.getIdentity(index))
      assertEquals(store.getSecret(index), store2.getSecret(index))
    }
  }

  @Test
  fun testSaveAndLoadEncryptedPskStore() {
    store.loadPskCredentials(ByteArrayInputStream(DATA))
    assertEquals(3, store.size())

    val out = ByteArrayOutputStream()
    store.savePskCredentials(out, secret)
    val encrypted = out.toByteArray()

    assertNotEquals(DATA, encrypted)
    val store2 = MultiPskFileStore()
    store2.loadPskCredentials(ByteArrayInputStream(encrypted), secret)
    assertEquals(store.size(), store2.size())

    for (index in 0 until store.size()) {
      assertEquals(store.getIdentity(index), store2.getIdentity(index))
      assertEquals(store.getSecret(index), store2.getSecret(index))
    }
  }

  @Test
  fun testSaveAndLoadEncryptedPskStoreWithWrongPassword() {
    store.loadPskCredentials(ByteArrayInputStream(DATA))
    assertEquals(3, store.size())

    val out = ByteArrayOutputStream()
    store.savePskCredentials(out, secret)
    val encrypted = out.toByteArray()

    assertNotEquals(DATA, encrypted)

    val key2 = SecretUtil.create("broken".toByteArray(), "PW")

    val store2 = MultiPskFileStore()
    store2.loadPskCredentials(ByteArrayInputStream(encrypted), key2)
    assertEquals(0, store2.size())
    assertTrue(store2.isDestroyed)
    SecretUtil.destroy(key2)
  }

  @Test
  fun testPskStoreRemove() {
    store.loadPskCredentials(ByteArrayInputStream(DATA))
    assertEquals(3, store.size())

    store.removeKey("me")
    assertEquals(2, store.size())
    assertNull(store.getSecret("me"))

    store.removeKey("you")
    assertEquals(1, store.size())
    assertNull(store.getSecret("you"))

    store.loadPskCredentials(ByteArrayInputStream(DATA))
    assertEquals(3, store.size())

    store.removeKey(0)
    assertEquals(2, store.size())
    assertNull(store.getSecret("me"))
  }
}
