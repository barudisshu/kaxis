/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */
package io.kaxis.util;

import static io.kaxis.dtls.TestCertificatesTools.*;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.kaxis.JceProvider;
import io.kaxis.util.SslContextUtil.*;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManager;
import javax.net.ssl.X509KeyManager;
import javax.security.auth.x500.X500Principal;

import io.kaxis.JceProvider;
import io.kaxis.dtls.TestCertificatesTools;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

class SslContextUtilCredentialsTest {

  public static final String KEY_STORE_PASSWORD_HEX = "656E6450617373";

  public static final String SERVER_P12_LOCATION =
      SslContextUtil.CLASSPATH_SCHEME + "certs/server.p12";
  public static final String SERVER_PEM_LOCATION =
      SslContextUtil.CLASSPATH_SCHEME + "certs/server.pem";
  public static final String SERVER_LARGE_PEM_LOCATION =
      SslContextUtil.CLASSPATH_SCHEME + "certs/serverLarge.pem";
  public static final String PUBLIC_KEY_PEM_LOCATION =
      SslContextUtil.CLASSPATH_SCHEME + "certs/ec_public.pem";

  public static final String ALIAS_SERVER = "server";
  public static final String ALIAS_CLIENT = "client";
  public static final String ALIAS_MISSING = "missing";
  public static final X500Principal DN_SERVER =
      new X500Principal("C=CN, L=Guangzhou, O=Kaxis IoT, OU=Kaxis, CN=cf-server");

  @Test
  void testLoadCredentials() throws IOException, GeneralSecurityException {
    Credentials credentials =
        SslContextUtil.loadCredentials(
            TestCertificatesTools.KEY_STORE_URI, ALIAS_SERVER, TestCertificatesTools.KEY_STORE_PASSWORD, TestCertificatesTools.KEY_STORE_PASSWORD);
    assertThat(credentials, is(notNullValue()));
    assertThat(credentials.getPrivateKey(), is(notNullValue()));
    assertThat(credentials.getCertificateChain(), is(notNullValue()));
    assertThat(credentials.getCertificateChain().length, is(greaterThan(0)));
    assertThat(credentials.getCertificateChain()[0], is(instanceOf(X509Certificate.class)));
    X509Certificate x509 = credentials.getCertificateChain()[0];
    assertThat(x509.getPublicKey(), is(notNullValue()));
    assertThat(x509.getSubjectX500Principal(), is(DN_SERVER));
  }

  /** Test, if a exception is thrown, when no credentials matches the alias. */
  @Test
  void testLoadCredentialsNotFound() throws IOException, GeneralSecurityException {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SslContextUtil.loadCredentials(
                TestCertificatesTools.KEY_STORE_URI, ALIAS_MISSING, TestCertificatesTools.KEY_STORE_PASSWORD, TestCertificatesTools.KEY_STORE_PASSWORD));
  }

  /** Test, if a exception is thrown, when the keyStoreUri doesn't point to a keystore. */
  @Test
  void testLoadCredentialsNoFile() throws IOException, GeneralSecurityException {
    assertThrows(
        IOException.class,
        () ->
            SslContextUtil.loadCredentials(
                TestCertificatesTools.KEY_STORE_URI + "no-file", ALIAS_SERVER, TestCertificatesTools.KEY_STORE_PASSWORD, TestCertificatesTools.KEY_STORE_PASSWORD));
  }

  /** Test, if a exception is thrown, when the keyStoreUri is null. */
  @Test
  void testLoadCredentialsNullUri() throws IOException, GeneralSecurityException {
    assertThrows(
        NullPointerException.class,
        () ->
            SslContextUtil.loadCredentials(
                null, ALIAS_SERVER, TestCertificatesTools.KEY_STORE_PASSWORD, TestCertificatesTools.KEY_STORE_PASSWORD));
  }

  /** Test, if a exception is thrown, when the store password is null. */
  @Test
  void testLoadCredentialsNoStorePassword() throws IOException, GeneralSecurityException {
    assertThrows(
        NullPointerException.class,
        () ->
            SslContextUtil.loadCredentials(TestCertificatesTools.KEY_STORE_URI, ALIAS_SERVER, null, TestCertificatesTools.KEY_STORE_PASSWORD));
  }

  /** Test, if a exception is thrown, when the key password is null. */
  @Test
  void testLoadCredentialsNoKeyPassword() throws IOException, GeneralSecurityException {
    assertThrows(
        NullPointerException.class,
        () ->
            SslContextUtil.loadCredentials(TestCertificatesTools.KEY_STORE_URI, ALIAS_SERVER, TestCertificatesTools.KEY_STORE_PASSWORD, null));
  }

  /** Test, if a exception is thrown, when the store password is wrong. */
  @Test
  void testLoadCredentialsWrongStorePassword() throws IOException, GeneralSecurityException {
    assertThrows(
        IOException.class,
        () ->
            SslContextUtil.loadCredentials(
                TestCertificatesTools.KEY_STORE_URI,
                ALIAS_SERVER,
                KEY_STORE_PASSWORD_HEX.toCharArray(),
                TestCertificatesTools.KEY_STORE_PASSWORD));
  }

  /** Test, if a exception is thrown, when the key password is wrong. */
  @Test
  void testLoadCredentialsWrongKeyPassword() throws IOException, GeneralSecurityException {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            SslContextUtil.loadCredentials(
                TestCertificatesTools.KEY_STORE_URI,
                ALIAS_SERVER,
                TestCertificatesTools.KEY_STORE_PASSWORD,
                KEY_STORE_PASSWORD_HEX.toCharArray()));
  }

  @Test
  void testLoadCredentialsSingleParameterWithoutAlias()
      throws IOException, GeneralSecurityException {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SslContextUtil.loadCredentials(
                TestCertificatesTools.KEY_STORE_URI
                    + SslContextUtil.PARAMETER_SEPARATOR
                    + KEY_STORE_PASSWORD_HEX
                    + SslContextUtil.PARAMETER_SEPARATOR
                    + KEY_STORE_PASSWORD_HEX
                    + SslContextUtil.PARAMETER_SEPARATOR));
  }

  @Test
  void testLoadCredentialsSingleParameter() throws IOException, GeneralSecurityException {
    Credentials credentials =
        SslContextUtil.loadCredentials(
            TestCertificatesTools.KEY_STORE_URI
                + SslContextUtil.PARAMETER_SEPARATOR
                + KEY_STORE_PASSWORD_HEX
                + SslContextUtil.PARAMETER_SEPARATOR
                + KEY_STORE_PASSWORD_HEX
                + SslContextUtil.PARAMETER_SEPARATOR
                + ALIAS_SERVER);
    assertThat(credentials, is(notNullValue()));
    assertThat(credentials.getPrivateKey(), is(notNullValue()));
    assertThat(credentials.getCertificateChain(), is(notNullValue()));
    assertThat(credentials.getCertificateChain().length, is(greaterThan(0)));
    assertThat(credentials.getCertificateChain()[0], is(instanceOf(X509Certificate.class)));
    X509Certificate x509 = credentials.getCertificateChain()[0];
    assertThat(x509.getPublicKey(), is(notNullValue()));
    assertThat(x509.getSubjectX500Principal(), is(DN_SERVER));
  }

  @Test
  void testLoadCertificateChain() throws IOException, GeneralSecurityException {
    X509Certificate[] chain =
        SslContextUtil.loadCertificateChain(TestCertificatesTools.KEY_STORE_URI, ALIAS_SERVER, TestCertificatesTools.KEY_STORE_PASSWORD);
    assertThat(chain, is(notNullValue()));
    assertThat(chain.length, is(greaterThan(0)));
    assertThat(chain[0].getPublicKey(), is(notNullValue()));
    assertThat(chain[0].getSubjectX500Principal(), is(DN_SERVER));
  }

  @Test
  void testLoadCertificateChainMissingAlias() throws IOException, GeneralSecurityException {
    assertThrows(
        NullPointerException.class,
        () -> SslContextUtil.loadCertificateChain(TestCertificatesTools.KEY_STORE_URI, null, TestCertificatesTools.KEY_STORE_PASSWORD));
  }

  @Test
  void testLoadCertificateChainEmptyAlias() throws IOException, GeneralSecurityException {
    assertThrows(
        IllegalArgumentException.class,
        () -> SslContextUtil.loadCertificateChain(TestCertificatesTools.KEY_STORE_URI, "", TestCertificatesTools.KEY_STORE_PASSWORD));
  }

  @Test
  void testLoadKeyManager() throws IOException, GeneralSecurityException {
    KeyManager[] manager =
        SslContextUtil.loadKeyManager(TestCertificatesTools.KEY_STORE_URI, null, TestCertificatesTools.KEY_STORE_PASSWORD, TestCertificatesTools.KEY_STORE_PASSWORD);
    assertThat(manager, is(notNullValue()));
    assertThat(manager.length, is(greaterThan(0)));
    assertThat(manager[0], is(instanceOf(X509KeyManager.class)));
  }

  /** Test, if a exception is thrown, when no certificate matches the filter. */
  @Test
  void testLoadKeyManagerCertificateNotFound() throws IOException, GeneralSecurityException {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            SslContextUtil.loadKeyManager(
                TestCertificatesTools.KEY_STORE_URI, "missing", TestCertificatesTools.KEY_STORE_PASSWORD, TestCertificatesTools.KEY_STORE_PASSWORD));
  }

  @Test
  void testCreateKeyManager() throws IOException, GeneralSecurityException {
    Credentials credentials =
        SslContextUtil.loadCredentials(
            TestCertificatesTools.KEY_STORE_URI, ALIAS_SERVER, TestCertificatesTools.KEY_STORE_PASSWORD, TestCertificatesTools.KEY_STORE_PASSWORD);
    KeyManager[] manager =
        SslContextUtil.createKeyManager(
            "test", credentials.getPrivateKey(), credentials.getCertificateChain());
    assertThat(manager, is(notNullValue()));
    assertThat(manager.length, is(greaterThan(0)));
    assertThat(manager[0], is(instanceOf(X509KeyManager.class)));
  }

  @Test
  void testCreateKeytManagerNullPrivateKey() throws IOException, GeneralSecurityException {
    assertThrows(
        NullPointerException.class,
        () -> {
          Credentials credentials =
              SslContextUtil.loadCredentials(
                  TestCertificatesTools.KEY_STORE_URI, ALIAS_SERVER, TestCertificatesTools.KEY_STORE_PASSWORD, TestCertificatesTools.KEY_STORE_PASSWORD);
          SslContextUtil.createKeyManager("test", null, credentials.getCertificateChain());
        });
  }

  @Test
  void testCreateKeytManagerNullCertChain() throws IOException, GeneralSecurityException {
    assertThrows(
        NullPointerException.class,
        () -> {
          Credentials credentials =
              SslContextUtil.loadCredentials(
                  TestCertificatesTools.KEY_STORE_URI, ALIAS_SERVER, TestCertificatesTools.KEY_STORE_PASSWORD, TestCertificatesTools.KEY_STORE_PASSWORD);
          SslContextUtil.createKeyManager("test", credentials.getPrivateKey(), null);
        });
  }

  @Test
  void testCreateKeyManagerEmptyCertChain() throws IOException, GeneralSecurityException {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          Credentials credentials =
              SslContextUtil.loadCredentials(
                  TestCertificatesTools.KEY_STORE_URI, ALIAS_SERVER, TestCertificatesTools.KEY_STORE_PASSWORD, TestCertificatesTools.KEY_STORE_PASSWORD);
          SslContextUtil.createKeyManager(
              "test", credentials.getPrivateKey(), new X509Certificate[0]);
        });
  }

  @Test
  void testLoadP12Credentials() throws IOException, GeneralSecurityException {
    Credentials credentials =
        SslContextUtil.loadCredentials(
            SERVER_P12_LOCATION, ALIAS_SERVER, TestCertificatesTools.KEY_STORE_PASSWORD, TestCertificatesTools.KEY_STORE_PASSWORD);
    assertThat(credentials, is(notNullValue()));
    assertThat(credentials.getPrivateKey(), is(notNullValue()));
    assertThat(credentials.getCertificateChain(), is(notNullValue()));
    assertThat(credentials.getCertificateChain().length, is(greaterThan(0)));
    assertThat(credentials.getCertificateChain()[0], is(instanceOf(X509Certificate.class)));
    X509Certificate x509 = credentials.getCertificateChain()[0];
    assertThat(x509.getPublicKey(), is(notNullValue()));
    assertThat(x509.getSubjectX500Principal(), is(DN_SERVER));
  }

  @Test
  void testLoadP12KeyManager() throws IOException, GeneralSecurityException {
    KeyManager[] manager =
        SslContextUtil.loadKeyManager(
            SERVER_P12_LOCATION, null, TestCertificatesTools.KEY_STORE_PASSWORD, TestCertificatesTools.KEY_STORE_PASSWORD);
    assertThat(manager, is(notNullValue()));
    assertThat(manager.length, is(greaterThan(0)));
    assertThat(manager[0], is(instanceOf(X509KeyManager.class)));
  }

  @Test
  void testLoadPemCredentials() throws IOException, GeneralSecurityException {
    Credentials credentials = SslContextUtil.loadCredentials(SERVER_PEM_LOCATION, null, null, null);
    assertThat(credentials, is(notNullValue()));
    assertThat(credentials.getPrivateKey(), is(notNullValue()));
    assertThat(credentials.getCertificateChain(), is(notNullValue()));
    assertThat(credentials.getCertificateChain().length, is(greaterThan(0)));
    assertThat(credentials.getCertificateChain()[0], is(instanceOf(X509Certificate.class)));
    X509Certificate x509 = credentials.getCertificateChain()[0];
    assertThat(x509.getPublicKey(), is(notNullValue()));
    assertThat(x509.getSubjectX500Principal(), is(DN_SERVER));
  }

  @Test
  void testLoadPemKeyManager() throws IOException, GeneralSecurityException {
    KeyManager[] manager = SslContextUtil.loadKeyManager(SERVER_PEM_LOCATION, null, null, null);
    assertThat(manager, is(notNullValue()));
    assertThat(manager.length, is(greaterThan(0)));
    assertThat(manager[0], is(instanceOf(X509KeyManager.class)));
  }

  @Test
  void testLoadLargePemKeyManager() throws IOException, GeneralSecurityException {
    KeyManager[] manager =
        SslContextUtil.loadKeyManager(SERVER_LARGE_PEM_LOCATION, null, null, null);
    assertThat(manager, is(notNullValue()));
    assertThat(manager.length, is(greaterThan(0)));
    assertThat(manager[0], is(instanceOf(X509KeyManager.class)));
  }

  @Test
  void testLoadPemPublicKey() throws IOException, GeneralSecurityException {
    PublicKey publicKey = SslContextUtil.loadPublicKey(PUBLIC_KEY_PEM_LOCATION, null, null);
    assertThat(publicKey, is(notNullValue()));
  }

  @Test
  void testLoadPemPrivateKey() throws IOException, GeneralSecurityException {
    PrivateKey privateKey = SslContextUtil.loadPrivateKey(SERVER_PEM_LOCATION, null, null, null);
    assertThat(privateKey, is(notNullValue()));
  }

  @Test
  void testLoadPemPrivateKeyV2() throws IOException, GeneralSecurityException {
    PrivateKey privateKey =
        SslContextUtil.loadPrivateKey(
            SslContextUtil.CLASSPATH_SCHEME + "certs/ec_private.pem", null, null, null);
    assertThat(privateKey, is(notNullValue()));
  }

  @Test
  void testLoadPemCredentialsV2() throws IOException, GeneralSecurityException {
    Credentials credentials =
        SslContextUtil.loadCredentials(
            SslContextUtil.CLASSPATH_SCHEME + "certs/ec_private.pem", null, null, null);
    assertThat(credentials, is(notNullValue()));
    assertThat(credentials.getPrivateKey(), is(notNullValue()));
    assertThat(credentials.getPublicKey(), is(notNullValue()));
    assertSigning(
        "PEMv2", credentials.getPrivateKey(), credentials.getPublicKey(), "SHA256withECDSA");
  }

  @Test
  void testLoadEdDsaCredentials() throws IOException, GeneralSecurityException {
    Assumptions.assumeTrue(JceProvider.isSupported(JceProvider.ED25519), "ED25519 requires JCE support!");
    assumeTrue(
        SslContextUtil.isAvailableFromUri(TestCertificatesTools.EDDSA_KEY_STORE_URI), TestCertificatesTools.EDDSA_KEY_STORE_URI + " missing!");

    Credentials credentials =
        SslContextUtil.loadCredentials(
            TestCertificatesTools.EDDSA_KEY_STORE_URI, "clienteddsa", TestCertificatesTools.KEY_STORE_PASSWORD, TestCertificatesTools.KEY_STORE_PASSWORD);
    assertThat(credentials, is(notNullValue()));
    assertThat(credentials.getCertificateChain(), is(notNullValue()));
    assertThat(credentials.getCertificateChain().length, is(greaterThan(0)));
    assertThat(credentials.getCertificateChain()[0].getPublicKey(), is(notNullValue()));
    assertSigning("JKS", credentials.getPrivateKey(), credentials.getPublicKey(), "ED25519");
  }

  @Test
  void testLoadPemPrivateKeyEd25519() throws IOException, GeneralSecurityException {
    assumeTrue(JceProvider.isSupported(JceProvider.ED25519), "ED25519 requires JCE support!");
    PrivateKey privateKey =
        SslContextUtil.loadPrivateKey(
            SslContextUtil.CLASSPATH_SCHEME + "certs/ed25519_private.pem", null, null, null);
    assertThat(privateKey, is(notNullValue()));
  }

  @Test
  void testLoadPemPublicKeyEd25519() throws IOException, GeneralSecurityException {
    assumeTrue(JceProvider.isSupported(JceProvider.ED25519), "ED25519 requires JCE support!");
    PublicKey publicKey =
        SslContextUtil.loadPublicKey(
            SslContextUtil.CLASSPATH_SCHEME + "certs/ed25519_public.pem", null, null);
    assertThat(publicKey, is(notNullValue()));
  }

  @Test
  void testLoadPemPrivateKeyEd448() throws IOException, GeneralSecurityException {
    assumeTrue(JceProvider.isSupported(JceProvider.ED448), "ED448 requires JCE support!");
    PrivateKey privateKey =
        SslContextUtil.loadPrivateKey(
            SslContextUtil.CLASSPATH_SCHEME + "certs/ed448_private.pem", null, null, null);
    assertThat(privateKey, is(notNullValue()));
  }

  @Test
  void testLoadPemPublicKeyEd448() throws IOException, GeneralSecurityException {
    assumeTrue(JceProvider.isSupported(JceProvider.ED448), "ED448 requires JCE support!");
    PublicKey publicKey =
        SslContextUtil.loadPublicKey(
            SslContextUtil.CLASSPATH_SCHEME + "certs/ed448_public.pem", null, null);
    assertThat(publicKey, is(notNullValue()));
  }
}
