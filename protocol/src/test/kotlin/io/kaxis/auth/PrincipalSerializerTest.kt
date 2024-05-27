/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.auth

import io.kaxis.dtls.DtlsTestTools
import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.PublicKey
import java.security.cert.Certificate
import kotlin.test.assertEquals

/**
 * Verifies behavior of [PrincipalSerializer].
 */
internal class PrincipalSerializerTest {
  companion object {
    private lateinit var publicKey: PublicKey
    private lateinit var certificateChain: Array<out Certificate>

    /**
     * Creates a public key to be used in test cases.
     * @throws GeneralSecurityException if the demo server certificate chain cannot be read.
     * @throws IOException if the demo server certificate chain cannot be read.
     */
    @BeforeAll
    @JvmStatic
    @Throws(GeneralSecurityException::class, IOException::class)
    fun init() {
      try {
        val generator = KeyPairGenerator.getInstance("RSA")
        val keyPair = generator.generateKeyPair()
        publicKey = keyPair.public
      } catch (e: NoSuchAlgorithmException) {
        // every VM is required to support RSA
      }
      certificateChain = DtlsTestTools.getServerCertificateChain()
    }

    fun testSerializedPSKIdentityCanBeDeserialized(pskIdentity: PreSharedKeyIdentity) {
      try {
        // WHEN serializing the identity to a byte array
        val writer = DatagramWriter()
        PrincipalSerializer.serialize(pskIdentity, writer)

        // THEN the resulting byte array can be used to re-instantiate the identity
        val identity = PrincipalSerializer.deserialize(DatagramReader(writer.toByteArray()))
        assertEquals(pskIdentity, identity)
      } catch (e: GeneralSecurityException) {
        // should not happen
        fail(e.message)
      }
    }
  }

  /**
   * Verifies that a pre-shared key identity that has been serialized using the serialize method can be re-instantiated
   * properly using the deserialize method.
   */
  @Test
  fun testSerializedPSKIdentityCanBeDeserialized() {
    Companion.testSerializedPSKIdentityCanBeDeserialized(PreSharedKeyIdentity("iot.kaxis.io", "acme"))
  }

  /**
   * Verifies that a pre-shared key identity without a virtual host that has been serialized using the serialize
   * method can be re-instantiated properly using the deserialize method.
   */
  @Test
  fun testSerializedPSKIdentityWithoutHostCanBeDeserialized() {
    Companion.testSerializedPSKIdentityCanBeDeserialized(PreSharedKeyIdentity("acme"))
  }

  /**
   * Verifies that a public key that has been serialized using the serialize method can be re-instantiated properly
   * using the deserialize method.
   * @throws GeneralSecurityException if the key cannot be deserialized.
   */
  @Test
  fun testSerializedRPKCanBeDeserialized() {
    val rpkIdentity = RawPublicKeyIdentity(publicKey)

    // WHEN serializing the raw public key identity to a byte array
    val writer = DatagramWriter()
    PrincipalSerializer.serialize(rpkIdentity, writer)

    // THEN the resulting byte array can be used to re-instantiate the public key
    val identity =
      PrincipalSerializer.deserialize(
        DatagramReader(writer.toByteArray()),
      ) as RawPublicKeyIdentity
    assertEquals(publicKey, identity.key)
    assertEquals(publicKey.algorithm, identity.key.algorithm)
  }

  /**
   * Verifies that a X509CertPath that has been serialized using the serialize method can be re-instantiated properly using
   * the deserialize method.
   * @throws GeneralSecurityException if the X509CertPath cannot be deserialized.
   */
  @Test
  fun testSerializedX509CertPathCanBeDeserialized() {
    val x509Identity = X509CertPath.fromCertificateChain(certificateChain.toList())

    // WHEN serializing the X509CertPath to a byte array
    val writer = DatagramWriter()
    PrincipalSerializer.serialize(x509Identity, writer)

    // THEN the resulting byte array can be used to re-instantiate the X509CertPath
    val identity = PrincipalSerializer.deserialize(DatagramReader(writer.toByteArray())) as X509CertPath
    assertEquals(x509Identity.name, identity.name)
    assertEquals(x509Identity.target, identity.target)
    assertEquals(x509Identity.path, identity.path)
  }
}
