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

import static io.kaxis.util.SslContextUtil.*;
import static io.kaxis.dtls.TestCertificatesTools.KEY_STORE_PASSWORD;
import static io.kaxis.dtls.TestCertificatesTools.KEY_STORE_URI;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.security.GeneralSecurityException;

import io.kaxis.dtls.TestCertificatesTools;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SslContextUtilConfigurationTest {

  public static final String KEY_STORE_PASSWORD_HEX = "656E6450617373";
  public static final String ALIAS_SERVER = "server";
  public static final String CUSTOM_SCHEME = "test://";
  public static final String CUSTOM_SCHEME_KEY_STORE_LOCATION = CUSTOM_SCHEME + "keyStore.jks";
  public static final String FILE_KEY_STORE_LOCATION =
      "../demo-certs/src/main/resources/keyStore.jks";
  public static final String INVALID_FILE_KEY_STORE_LOCATION = "keyStore.jks";

  public static final String CUSTOM_ENDING = ".cks";
  public static final String CUSTOM_TYPE = "CKS";

  private TestInputStreamFactory testFactory;

  @BeforeEach
  void init() {
    SslContextUtil.configureDefaults();
    testFactory = new TestInputStreamFactory();
    testFactory.stream =
        SslContextUtil.class.getClassLoader().getResourceAsStream("certs/keyStore.jks");
  }

  @AfterEach
  void close() {
    try {
      testFactory.close();
    } catch (IOException e) {
    }
  }

  @Test
  void testLoadKeyStoreFromClasspath() throws IOException, GeneralSecurityException {
    Credentials credentials =
        SslContextUtil.loadCredentials(
            TestCertificatesTools.KEY_STORE_URI, ALIAS_SERVER, TestCertificatesTools.KEY_STORE_PASSWORD, TestCertificatesTools.KEY_STORE_PASSWORD);
    assertThat(credentials, is(notNullValue()));
  }

  @Test
  void testValidKeyStoreWithoutScheme() throws IOException, GeneralSecurityException {
    Credentials credentials =
        SslContextUtil.loadCredentials(
            TestCertificatesTools.KEY_STORE_URI, ALIAS_SERVER, TestCertificatesTools.KEY_STORE_PASSWORD, TestCertificatesTools.KEY_STORE_PASSWORD);
    assertThat(credentials, is(notNullValue()));
  }

  @Test
  void testInvalidKeyStoreWithoutScheme() throws IOException, GeneralSecurityException {
    assertThrows(
        IOException.class,
        () ->
            SslContextUtil.loadCredentials(
                INVALID_FILE_KEY_STORE_LOCATION,
                ALIAS_SERVER,
                TestCertificatesTools.KEY_STORE_PASSWORD,
                TestCertificatesTools.KEY_STORE_PASSWORD));
  }

  @Test
  void testNotConfiguredScheme() throws IOException, GeneralSecurityException {
    assertThrows(
        MalformedURLException.class,
        () ->
            SslContextUtil.loadCredentials(
                CUSTOM_SCHEME_KEY_STORE_LOCATION,
                ALIAS_SERVER,
                TestCertificatesTools.KEY_STORE_PASSWORD,
                TestCertificatesTools.KEY_STORE_PASSWORD));
  }

  @Test
  void testConfigureInputStreamFactoryWithoutScheme() throws IOException, GeneralSecurityException {
    assertThrows(NullPointerException.class, () -> SslContextUtil.configure(null, testFactory));
  }

  @Test
  void testConfigureInputStreamFactoryWithInvalidScheme()
      throws IOException, GeneralSecurityException {
    assertThrows(
        IllegalArgumentException.class, () -> SslContextUtil.configure("test:", testFactory));
  }

  @Test
  void testConfigureInputStreamFactoryWithoutFactory()
      throws IOException, GeneralSecurityException {
    assertThrows(
        NullPointerException.class,
        () -> SslContextUtil.configure(CUSTOM_SCHEME, (SslContextUtil.InputStreamFactory) null));
  }

  @Test
  void testConfigureInputStreamFactory() throws IOException, GeneralSecurityException {
    SslContextUtil.configure(CUSTOM_SCHEME, testFactory);
    Credentials credentials =
        SslContextUtil.loadCredentials(
            CUSTOM_SCHEME_KEY_STORE_LOCATION, ALIAS_SERVER, TestCertificatesTools.KEY_STORE_PASSWORD, TestCertificatesTools.KEY_STORE_PASSWORD);
    assertThat(credentials, is(notNullValue()));
    assertThat(testFactory.uri, is(CUSTOM_SCHEME_KEY_STORE_LOCATION));
  }

  @Test
  void testLoadKeyStoreFromClasspathWithCustomConfiguration()
      throws IOException, GeneralSecurityException {
    testFactory.close();
    SslContextUtil.configure(CUSTOM_SCHEME, testFactory);
    Credentials credentials =
        SslContextUtil.loadCredentials(
            TestCertificatesTools.KEY_STORE_URI, ALIAS_SERVER, TestCertificatesTools.KEY_STORE_PASSWORD, TestCertificatesTools.KEY_STORE_PASSWORD);
    assertThat(credentials, is(notNullValue()));
  }

  @Test
  void testConfigureKeyStoreTypeWithoutEnding() throws IOException, GeneralSecurityException {
    assertThrows(
        NullPointerException.class,
        () -> SslContextUtil.configure(null, new KeyStoreType(CUSTOM_TYPE)));
  }

  @Test
  void testConfigureKeyStoreTypeWithoutType() throws IOException, GeneralSecurityException {
    assertThrows(
        NullPointerException.class,
        () -> SslContextUtil.configure(CUSTOM_ENDING, (KeyStoreType) null));
  }

  @Test
  void testConfigureKeyStoreTypeWithInvalidEnding() throws IOException, GeneralSecurityException {
    assertThrows(
        IllegalArgumentException.class,
        () -> SslContextUtil.configure(CUSTOM_TYPE, new KeyStoreType(CUSTOM_TYPE)));
  }

  @Test
  void testConfigureKeyStoreTypeWithInvalidType() throws IOException, GeneralSecurityException {
    assertThrows(
        IllegalArgumentException.class,
        () -> SslContextUtil.configure(CUSTOM_ENDING, new KeyStoreType("")));
  }

  @Test
  void testConfigureKeyStoreType() throws IOException, GeneralSecurityException {
    try {
      SslContextUtil.configure(SslContextUtil.JKS_ENDING, new KeyStoreType(CUSTOM_TYPE));
      SslContextUtil.loadCredentials(
          TestCertificatesTools.KEY_STORE_URI, ALIAS_SERVER, TestCertificatesTools.KEY_STORE_PASSWORD, TestCertificatesTools.KEY_STORE_PASSWORD);
      fail("custom key store type \"" + CUSTOM_TYPE + "\" is not intended to be supported!");
    } catch (GeneralSecurityException ex) {
      assertThat(ex.getMessage(), containsString(CUSTOM_TYPE));
    }
  }

  private class TestInputStreamFactory implements SslContextUtil.InputStreamFactory {

    String uri;
    InputStream stream;

    public void close() throws IOException {
      if (stream != null) {
        stream.close();
        stream = null;
      }
    }

    @Override
    public InputStream create(String uri) throws IOException {
      this.uri = uri;
      InputStream result = stream;
      stream = null;
      return result;
    }
  }
}
