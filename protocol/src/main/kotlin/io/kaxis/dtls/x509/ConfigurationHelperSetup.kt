/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls.x509

/**
 * Setup for certificate configuration helper.
 *
 * [CertificateProvider] and [NewAdvancedCertificateVerifier] implementation may implement
 * this interface as well in order to participate in the automatic default configuration
 * and configuration verification.
 */
fun interface ConfigurationHelperSetup {
  /**
   * Setup the helper.
   *
   * Add all public key, certificate chains, or trusted certificates to the provided helper.
   *
   * @throws NullPointerException if the helper is `null`.
   */
  fun setupConfigurationHelper(helper: CertificateConfigurationHelper?)
}
