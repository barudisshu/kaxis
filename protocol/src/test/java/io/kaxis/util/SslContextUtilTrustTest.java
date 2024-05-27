/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */
package io.kaxis.util;

import static io.kaxis.dtls.TestCertificatesTools.TRUST_STORE_PASSWORD;
import static io.kaxis.dtls.TestCertificatesTools.TRUST_STORE_URI;
import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.kaxis.JceProvider;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import io.kaxis.JceProvider;
import io.kaxis.dtls.TestCertificatesTools;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

class SslContextUtilTrustTest {

	public static final String TRUST_STORE_PASSWORD_HEX = "726F6F7450617373";
	public static final String TRUST_P12_LOCATION = SslContextUtil.CLASSPATH_SCHEME + "certs/trustStore.p12";
	public static final String TRUST_PEM_LOCATION = SslContextUtil.CLASSPATH_SCHEME + "certs/trustStore.pem";
	public static final String SINGLE_TRUST_PEM_LOCATION = SslContextUtil.CLASSPATH_SCHEME + "certs/rootTrustStore.pem";

	public static final char[] TRUST_STORE_WRONG_PASSWORD = "wrongPass".toCharArray();

	public static final String ALIAS_CA = "ca";
	public static final String ALIAS_MISSING = "missing";
	public static final X500Principal DN_CA = new X500Principal("C=CN, L=Guangzhou, O=Kaxis IoT, OU=Kaxis, CN=cf-ca");
	public static final X500Principal DN_CA2 = new X500Principal("C=CN, L=Guangzhou, O=Kaxis IoT, OU=Kaxis, CN=cf-ca2");
	public static final X500Principal DN_CA_RSA = new X500Principal("C=CN, L=Guangzhou, O=Kaxis IoT, OU=Kaxis, CN=cf-ca-rsa");
	public static final X500Principal DN_ROOT = new X500Principal("C=CN, L=Guangzhou, O=Kaxis IoT, OU=Kaxis, CN=cf-root");

	@Test
	void testLoadTrustedCertificates() throws IOException, GeneralSecurityException {
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(TestCertificatesTools.TRUST_STORE_URI, null,
				TestCertificatesTools.TRUST_STORE_PASSWORD);
		assertThat(trustedCertificates, is(notNullValue()));
		assertThat(trustedCertificates.length, is(5));
		assertThat(trustedCertificates[0], is(instanceOf(X509Certificate.class)));
		assertThat(trustedCertificates[0].getPublicKey(), is(notNullValue()));
		X509Certificate x509 = (X509Certificate) trustedCertificates[0];
		assertThat(x509.getSubjectX500Principal(), anyOf(is(DN_CA), is(DN_CA2), is(DN_CA_RSA), is(DN_ROOT)));
	}

	@Test
	void testLoadFilteredTrustedCertificates() throws IOException, GeneralSecurityException {
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(TestCertificatesTools.TRUST_STORE_URI, ALIAS_CA,
				TestCertificatesTools.TRUST_STORE_PASSWORD);
		assertThat(trustedCertificates, is(notNullValue()));
		assertThat(trustedCertificates.length, is(1));
		assertThat(trustedCertificates[0], is(instanceOf(X509Certificate.class)));
		X509Certificate x509 = (X509Certificate) trustedCertificates[0];
		assertThat(x509.getSubjectX500Principal(), is(DN_CA));
	}

	/**
	 * Test, if a exception is thrown, when no certificate matches the filter.
	 */
	@Test
	void testLoadFilteredTrustedCertificatesNotFound() throws IOException, GeneralSecurityException {
		assertThrows(IllegalArgumentException.class, () -> SslContextUtil.loadTrustedCertificates(TestCertificatesTools.TRUST_STORE_URI, ALIAS_MISSING, TestCertificatesTools.TRUST_STORE_PASSWORD));
	}

	/**
	 * Test, if a exception is thrown, when the keyStoreUri doesn't point to a
	 * keystore.
	 */
	@Test
	void testLoadTrustedCertificatesNoFile() throws IOException, GeneralSecurityException {
		assertThrows(IOException.class, () -> SslContextUtil.loadTrustedCertificates(TestCertificatesTools.TRUST_STORE_URI + "no-file", null, TestCertificatesTools.TRUST_STORE_PASSWORD));
	}

	/**
	 * Test, if a exception is thrown, when the keyStoreUri is null.
	 */
	@Test
	void testLoadTrustedCertificatesNullUri() throws IOException, GeneralSecurityException {
		assertThrows(NullPointerException.class, () -> SslContextUtil.loadTrustedCertificates(null, null, TestCertificatesTools.TRUST_STORE_PASSWORD));
	}

	/**
	 * Test, if a exception is thrown, when the password is null.
	 */
	@Test
	void testLoadTrustedCertificatesNoPassword() throws IOException, GeneralSecurityException {
		assertThrows(NullPointerException.class, () -> SslContextUtil.loadTrustedCertificates(TestCertificatesTools.TRUST_STORE_URI, null, null));
	}

	/**
	 * Test, if a exception is thrown, when the password is wrong.
	 */
	@Test
	void testLoadTrustedCertificatesWrongPassword() throws IOException, GeneralSecurityException {
		assertThrows(IOException.class, () -> SslContextUtil.loadTrustedCertificates(TestCertificatesTools.TRUST_STORE_URI, null, TRUST_STORE_WRONG_PASSWORD));
	}

	@Test
	void testLoadTrustedCertificatesSingleParameterWithoutAlias() throws IOException, GeneralSecurityException {
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(TestCertificatesTools.TRUST_STORE_URI
				+ SslContextUtil.PARAMETER_SEPARATOR + TRUST_STORE_PASSWORD_HEX + SslContextUtil.PARAMETER_SEPARATOR);
		assertThat(trustedCertificates, is(notNullValue()));
		assertThat(trustedCertificates.length, is(greaterThan(0)));
		assertThat(trustedCertificates[0], is(instanceOf(X509Certificate.class)));
		assertThat(trustedCertificates[0].getPublicKey(), is(notNullValue()));
	}

	@Test
	void testLoadTrustedCertificatesSingleParameter() throws IOException, GeneralSecurityException {
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(TestCertificatesTools.TRUST_STORE_URI
				+ SslContextUtil.PARAMETER_SEPARATOR + TRUST_STORE_PASSWORD_HEX + SslContextUtil.PARAMETER_SEPARATOR
				+ ALIAS_CA);
		assertThat(trustedCertificates, is(notNullValue()));
		assertThat(trustedCertificates.length, is(1));
		assertThat(trustedCertificates[0], is(instanceOf(X509Certificate.class)));
		X509Certificate x509 = (X509Certificate) trustedCertificates[0];
		assertThat(x509.getSubjectX500Principal(), is(DN_CA));
	}

	@Test
	void testLoadTrustedCertificatesSingleParameterError() throws IOException, GeneralSecurityException {
		assertThrows(IllegalArgumentException.class, () ->SslContextUtil.loadTrustedCertificates(TestCertificatesTools.TRUST_STORE_URI
				+ SslContextUtil.PARAMETER_SEPARATOR + TRUST_STORE_PASSWORD_HEX));
	}

	@Test
	void testLoadTrustManager() throws IOException, GeneralSecurityException {
		TrustManager[] manager = SslContextUtil.loadTrustManager(TestCertificatesTools.TRUST_STORE_URI, null, TestCertificatesTools.TRUST_STORE_PASSWORD);
		assertThat(manager, is(notNullValue()));
		assertThat(manager.length, is(greaterThan(0)));
		assertThat(manager[0], is(instanceOf(X509TrustManager.class)));
	}

	/**
	 * Test, if a exception is thrown, when no certificate matches the filter.
	 */
	@Test
	void testLoadTrustManagerCertificateNotFound() throws IOException, GeneralSecurityException {
		assertThrows(IllegalArgumentException.class, () -> SslContextUtil.loadTrustManager(TestCertificatesTools.TRUST_STORE_URI, ALIAS_MISSING, TestCertificatesTools.TRUST_STORE_PASSWORD));
	}

	@Test
	void testCreateTrustManager() throws IOException, GeneralSecurityException {
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(TestCertificatesTools.TRUST_STORE_URI, null,
				TestCertificatesTools.TRUST_STORE_PASSWORD);
		TrustManager[] manager = SslContextUtil.createTrustManager("test", trustedCertificates);
		assertThat(manager, is(notNullValue()));
		assertThat(manager.length, is(greaterThan(0)));
		assertThat(manager[0], is(instanceOf(X509TrustManager.class)));
	}

	@Test
	void testCreateTrustManagerNullCertificates() throws IOException, GeneralSecurityException {
		assertThrows(NullPointerException.class, () -> SslContextUtil.createTrustManager("test", null));
	}

	@Test
	void testCreateTrustManagerEmptyCertificates() throws IOException, GeneralSecurityException {
		assertThrows(IllegalArgumentException.class, () -> SslContextUtil.createTrustManager("test", new Certificate[0]));
	}

	@Test
	void testLoadP12TrustedCertificates() throws IOException, GeneralSecurityException {
		Assumptions.assumeTrue(JceProvider.hasStrongEncryption(), "requires strong encryption");
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(TRUST_P12_LOCATION, null, TestCertificatesTools.TRUST_STORE_PASSWORD);
		assertThat(trustedCertificates, is(notNullValue()));
		assertThat(trustedCertificates.length, is(5));
		X509Certificate x509 = (X509Certificate) trustedCertificates[0];
		assertThat(x509.getPublicKey(), is(notNullValue()));
		assertThat(x509.getSubjectX500Principal(), anyOf(is(DN_CA), is(DN_CA2), is(DN_CA_RSA), is(DN_ROOT)));
	}

	@Test
	void testLoadP12TrustedCertificatesWithAlias() throws IOException, GeneralSecurityException {
		assumeTrue(JceProvider.hasStrongEncryption(), "requires strong encryption");
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(TRUST_P12_LOCATION, ALIAS_CA, TestCertificatesTools.TRUST_STORE_PASSWORD);
		assertThat(trustedCertificates, is(notNullValue()));
		assertThat(trustedCertificates.length, is(1));
		X509Certificate x509 = (X509Certificate) trustedCertificates[0];
		assertThat(x509.getPublicKey(), is(notNullValue()));
		assertThat(x509.getSubjectX500Principal(), is(DN_CA));
	}

	@Test
	void testLoadP12TrustManager() throws IOException, GeneralSecurityException {
		assumeTrue(JceProvider.hasStrongEncryption(), "requires strong encryption");
		TrustManager[] manager = SslContextUtil.loadTrustManager(TRUST_P12_LOCATION, null, TestCertificatesTools.TRUST_STORE_PASSWORD);
		assertThat(manager, is(notNullValue()));
		assertThat(manager.length, is(greaterThan(0)));
		assertThat(manager[0], is(instanceOf(X509TrustManager.class)));
	}

	@Test
	void testLoadP12TrustManagerWithAlias() throws IOException, GeneralSecurityException {
		assumeTrue(JceProvider.hasStrongEncryption(), "requires strong encryption");
		TrustManager[] manager = SslContextUtil.loadTrustManager(TRUST_P12_LOCATION, ALIAS_CA, TestCertificatesTools.TRUST_STORE_PASSWORD);
		assertThat(manager, is(notNullValue()));
		assertThat(manager.length, is(greaterThan(0)));
		assertThat(manager[0], is(instanceOf(X509TrustManager.class)));
	}

	@Test
	void testLoadPemTrustedCertificates() throws IOException, GeneralSecurityException {
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(TRUST_PEM_LOCATION, null, null);
		assertThat(trustedCertificates, is(notNullValue()));
		assertThat(trustedCertificates.length, is(5));
		X509Certificate x509 = (X509Certificate) trustedCertificates[0];
		assertThat(x509.getPublicKey(), is(notNullValue()));
		assertThat(x509.getSubjectX500Principal(), anyOf(is(DN_CA), is(DN_CA2), is(DN_CA_RSA), is(DN_ROOT)));
	}

	@Test
	void testLoadPemTrustManager() throws IOException, GeneralSecurityException {
		TrustManager[] manager = SslContextUtil.loadTrustManager(TRUST_PEM_LOCATION, null, null);
		assertThat(manager, is(notNullValue()));
		assertThat(manager.length, is(greaterThan(0)));
		assertThat(manager[0], is(instanceOf(X509TrustManager.class)));
	}

	@Test
	void testLoadPemTrustedSingleCertificate() throws IOException, GeneralSecurityException {
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(SINGLE_TRUST_PEM_LOCATION);
		assertThat(trustedCertificates, is(notNullValue()));
		assertThat(trustedCertificates.length, is(1));
		X509Certificate x509 = (X509Certificate) trustedCertificates[0];
		assertThat(x509.getPublicKey(), is(notNullValue()));
		assertThat(x509.getSubjectX500Principal(), is(DN_ROOT));
	}

}
