/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.extension

import io.kaxis.extension.generator.KaxisBcFabric
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.operator.OperatorCreationException
import java.io.File
import java.io.IOException
import java.io.StringWriter
import java.io.Writer
import java.util.*

class JcaMiscPemGroove(
  val caGroove: KaxisBcFabric.JcaKeyPair,
  val serverGroove: KaxisBcFabric.JcaKeyPair,
  val clientGroove: KaxisBcFabric.JcaKeyPair,
) : AbstractMiscPemGroove() {
  /**
   *
   */
  override val id: String
    get() = UUID.randomUUID().toString().replace("-", "")

  /**
   * Export CA to directory.
   */
  @Throws(IOException::class, OperatorCreationException::class)
  @Suppress("kotlin:S107")
  fun exportCaToFolder(
    folder: File,
    x509File: File,
    keyFile: File,
    pkcs8File: File,
    pkcs12File: File,
    keyEncryptionAlg: ASN1ObjectIdentifier,
    password: String? = null,
    keystorePasswd: String? = null,
  ) {
    exportToFolder(
      caGroove.x509Certificate,
      caGroove.x509Certificate,
      caGroove.privateKey,
      folder,
      x509File,
      keyFile,
      pkcs8File,
      pkcs12File,
      keyEncryptionAlg,
      password,
      keystorePasswd,
    )
  }

  @Throws(IOException::class, OperatorCreationException::class)
  fun exportCaToWriter(
    x509Writer: Writer,
    keyWriter: Writer,
    pkcs8Writer: Writer,
    pkcs12Writer: Writer,
    keyEncryptionAlg: ASN1ObjectIdentifier,
    password: String? = null,
    keystorePasswd: String? = null,
  ) {
    exportToWriter(
      caGroove.x509Certificate,
      caGroove.x509Certificate,
      caGroove.privateKey,
      x509Writer,
      keyWriter,
      pkcs8Writer,
      pkcs12Writer,
      keyEncryptionAlg,
      password,
      keystorePasswd,
    )
  }

  @Throws(IOException::class, OperatorCreationException::class)
  fun exportCaToString(
    keyEncryptionAlg: ASN1ObjectIdentifier,
    password: String? = null,
    keystorePasswd: String? = null,
  ): Array<String> {
    return exportToString { x509Writer, keyWriter, pkcs8Writer, pkcs12Writer ->
      exportCaToWriter(
        x509Writer,
        keyWriter,
        pkcs8Writer,
        pkcs12Writer,
        keyEncryptionAlg,
        password,
        keystorePasswd,
      )
    }
  }

  /**
   * Export Server to directory.
   */
  @Throws(IOException::class, OperatorCreationException::class)
  @Suppress("kotlin:S107")
  fun exportServerToFolder(
    folder: File,
    x509File: File,
    keyFile: File,
    pkcs8File: File,
    pkcs12File: File,
    keyEncryptionAlg: ASN1ObjectIdentifier,
    password: String? = null,
    keystorePasswd: String? = null,
  ) {
    exportToFolder(
      caGroove.x509Certificate,
      serverGroove.x509Certificate,
      serverGroove.privateKey,
      folder,
      x509File,
      keyFile,
      pkcs8File,
      pkcs12File,
      keyEncryptionAlg,
      password,
      keystorePasswd,
    )
  }

  @Throws(IOException::class, OperatorCreationException::class)
  fun exportServerToWriter(
    x509Writer: Writer,
    keyWriter: Writer,
    pkcs8Writer: Writer,
    pkcs12Writer: Writer,
    keyEncryptionAlg: ASN1ObjectIdentifier,
    password: String? = null,
    keystorePasswd: String? = null,
  ) {
    exportToWriter(
      caGroove.x509Certificate,
      serverGroove.x509Certificate,
      serverGroove.privateKey,
      x509Writer,
      keyWriter,
      pkcs8Writer,
      pkcs12Writer,
      keyEncryptionAlg,
      password,
      keystorePasswd,
    )
  }

  @Throws(IOException::class, OperatorCreationException::class)
  fun exportServerToString(
    keyEncryptionAlg: ASN1ObjectIdentifier,
    password: String? = null,
    keystorePasswd: String? = null,
  ): Array<String> {
    return exportToString { x509Writer, keyWriter, pkcs8Writer, pkcs12Writer ->
      exportServerToWriter(
        x509Writer,
        keyWriter,
        pkcs8Writer,
        pkcs12Writer,
        keyEncryptionAlg,
        password,
        keystorePasswd,
      )
    }
  }

  @Throws(IOException::class, OperatorCreationException::class)
  private fun exportToString(block: (StringWriter, StringWriter, StringWriter, StringWriter) -> Unit): Array<String> {
    val x509Str: String
    val keyStr: String
    val pkcs8Str: String
    val pkcs12Str: String

    StringWriter().use { x509Writer ->
      StringWriter().use { keyWriter ->
        StringWriter().use { pkcs8Writer ->
          StringWriter().use { pkcs12Writer ->

            block(x509Writer, keyWriter, pkcs8Writer, pkcs12Writer)
            val x509 = x509Writer.buffer
            val key = keyWriter.buffer
            val pkcs8 = pkcs8Writer.buffer
            val pkcs12 = pkcs12Writer.buffer

            x509Str = String(x509)
            keyStr = String(key)
            pkcs8Str = String(pkcs8)
            pkcs12Str = String(pkcs12)
          }
        }
      }
    }

    return arrayOf(x509Str, keyStr, pkcs8Str, pkcs12Str)
  }

  /**
   * Export client to directory.
   */
  @Throws(IOException::class, OperatorCreationException::class)
  @Suppress("kotlin:S107")
  fun exportClientToFolder(
    folder: File,
    x509File: File,
    keyFile: File,
    pkcs8File: File,
    pkcs12File: File,
    keyEncryptionAlg: ASN1ObjectIdentifier,
    password: String? = null,
    keystorePasswd: String? = null,
  ) {
    exportToFolder(
      caGroove.x509Certificate,
      clientGroove.x509Certificate,
      clientGroove.privateKey,
      folder,
      x509File,
      keyFile,
      pkcs8File,
      pkcs12File,
      keyEncryptionAlg,
      password,
      keystorePasswd,
    )
  }

  @Throws(IOException::class, OperatorCreationException::class)
  fun exportClientToWriter(
    x509Writer: Writer,
    keyWriter: Writer,
    pkcs8Writer: Writer,
    pkcs12Writer: Writer,
    keyEncryptionAlg: ASN1ObjectIdentifier,
    password: String? = null,
    keystorePasswd: String? = null,
  ) {
    exportToWriter(
      caGroove.x509Certificate,
      clientGroove.x509Certificate,
      clientGroove.privateKey,
      x509Writer,
      keyWriter,
      pkcs8Writer,
      pkcs12Writer,
      keyEncryptionAlg,
      password,
      keystorePasswd,
    )
  }

  @Throws(IOException::class, OperatorCreationException::class)
  fun exportClientToString(
    keyEncryptionAlg: ASN1ObjectIdentifier,
    password: String? = null,
    keystorePasswd: String? = null,
  ): Array<String> {
    return exportToString { x509Writer, keyWriter, pkcs8Writer, pkcs12Writer ->
      exportClientToWriter(
        x509Writer,
        keyWriter,
        pkcs8Writer,
        pkcs12Writer,
        keyEncryptionAlg,
        password,
        keystorePasswd,
      )
    }
  }
}
