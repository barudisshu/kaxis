/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
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
