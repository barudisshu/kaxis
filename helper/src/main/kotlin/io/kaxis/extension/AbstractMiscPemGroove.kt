/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.extension

import io.kaxis.extension.generator.KaxisBcFabric
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.operator.OperatorCreationException
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.io.File
import java.io.IOException
import java.io.Writer
import java.security.PrivateKey
import java.security.cert.X509Certificate

/**
 * Pojo store code gen crypto instance.
 */
abstract class AbstractMiscPemGroove {
  private val log: Logger = LoggerFactory.getLogger(this::class.java)

  abstract val id: String

  /**
   * Export to Folder.
   * @throws IOException io
   * @throws OperatorCreationException operator
   */
  @Throws(IOException::class, OperatorCreationException::class)
  @Suppress("kotlin:S107")
  fun exportToFolder(
    rootCertificate: X509Certificate,
    x509Certificate: X509Certificate,
    privateKey: PrivateKey,
    folder: File,
    x509File: File,
    keyFile: File,
    pkcs8File: File,
    pkcs12File: File,
    keyEncryptionAlg: ASN1ObjectIdentifier,
    keyPasswd: String? = null,
    keystorePasswd: String? = null,
  ) {
    if (!folder.isDirectory) {
      throw IOException("you must provide the basic directory to export file")
    }
    log.info("pgp id: {} with algorithm: {} Files generated.", id, x509Certificate.sigAlgName)
    KaxisBcFabric.exportX509ToFileBase64Encoded(x509Certificate, x509File)
    KaxisBcFabric.exportKeyPairToFile(privateKey, keyFile, pkcs8File, keyEncryptionAlg, keyPasswd)
    KaxisBcFabric.exportPfxPdu(
      rootCertificate,
      x509Certificate,
      privateKey,
      pkcs12File,
      keyEncryptionAlg,
      keystorePasswd,
    )
  }

  /**
   * The alternative way that writer to memory.
   * @throws IOException io
   * @throws OperatorCreationException operator
   */
  @Throws(IOException::class, OperatorCreationException::class)
  @Suppress("kotlin:S107")
  fun exportToWriter(
    rootCertificate: X509Certificate,
    x509Certificate: X509Certificate,
    privateKey: PrivateKey,
    x509Writer: Writer,
    keyWriter: Writer,
    pkcs8Writer: Writer,
    pkcs12Writer: Writer,
    keyEncryptionAlg: ASN1ObjectIdentifier,
    keyPasswd: String? = null,
    keystorePasswd: String? = null,
  ) {
    log.info("pgp id: {} with algorithm: {} objects generated.", id, x509Certificate.sigAlgName)
    KaxisBcFabric.exportX509ToFileBase64Encoded(x509Certificate, x509Writer)
    KaxisBcFabric.exportKeyPairToFile(privateKey, keyWriter, pkcs8Writer, keyEncryptionAlg, keyPasswd)
    KaxisBcFabric.exportPfxPdu(
      rootCertificate,
      x509Certificate,
      privateKey,
      pkcs12Writer,
      keyEncryptionAlg,
      keystorePasswd,
    )
  }
}
