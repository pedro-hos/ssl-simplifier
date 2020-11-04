package org.ssls.services;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import javax.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.Test;
import org.ssls.model.KeyStoreInfo;
import org.ssls.model.TrustStoreInfo;
import org.ssls.model.TrustedCertificate;

import io.quarkus.test.junit.QuarkusTest;

/**
 * 
 * @author pedro-hos
 *
 */

@QuarkusTest
public class SSLServiceTest {
	
	@Inject
	SSLService sslService;
	
	@ConfigProperty(name = "regex.ignoring.unavailable.cipher")
	String ignoringUnavaiableCipherRegex;
	
	@ConfigProperty(name = "regex.ignoring.unsuported.cipher")
	String ignoringUnsuportedCipherRegex;
	
	@ConfigProperty(name = "regex.ignoring.disabled.cipher")
	String ignoringDisabledCipherRegex;
	
	@Test
	public void shoulExceptionThrown() throws IOException {
		assertThrows(IOException.class, () -> {
			sslService.readFile("");
		});
	}
	
	@Test
	public void shouldExtractIgnoringCiphers() {
		
		String content = "2020-07-14 13:00:51,105 INFO  [org.jboss.modules] (main) JBoss Modules version 1.5.3.Final-redhat-1\n"
				+ "2020-07-14 13:00:51,797 INFO  [org.jboss.msc] (main) JBoss MSC version 1.2.7.SP1-redhat-1\n"
				+ "2020-07-14 13:00:52,072 INFO  [org.jboss.as] (MSC service thread 1-8) WFLYSRV0049: JBoss EAP 7.0.6.GA (WildFly Core 2.1.15.Final-redhat-1) starting\n"
				+ "2020-07-14 13:00:52,074 DEBUG [org.jboss.as.config] (MSC service thread 1-8) Configured system properties:"
				+ "2020-07-14 13:01:49,846 INFO  [stdout] (default task-1) Ignoring unavailable cipher suite: TLS_DH_anon_WITH_AES_256_CBC_SHA\n"
				+ "2020-07-14 13:01:49,891 INFO  [stdout] (default task-1) Ignoring unavailable cipher suite: TLS_DH_anon_WITH_AES_256_CBC_SHA256\n"
				+ "2020-07-14 13:01:49,891 INFO  [stdout] (default task-1) Ignoring unavailable cipher suite: TLS_RSA_WITH_AES_256_CBC_SHA\n"
				+ "2020-07-14 13:01:49,892 INFO  [stdout] (default task-1) Ignoring unavailable cipher suite: TLS_DHE_RSA_WITH_AES_256_GCM_SHA384\n"
				+ "2020-07-14 13:01:49,892 INFO  [stdout] (default task-1) Ignoring unavailable cipher suite: TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA\n"
				+ "2020-07-14 13:01:49,892 INFO  [stdout] (default task-1) Ignoring unavailable cipher suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\n"
				+ "2020-07-14 13:25:21,012 INFO  [org.wildfly.extension.undertow] (MSC service thread 1-6) WFLYUT0019: Host default-host stopping\n"
				+ "2020-07-14 13:25:21,014 INFO  [org.wildfly.extension.messaging-activemq] (MSC service thread 1-5) WFLYMSGAMQ0006: Unbound messaging object to jndi name java:jboss/DefaultJMSConnectionFactory\n"
				+ "2020-07-14 13:25:21,014 INFO  [org.jboss.as.connector.subsystems.datasources] (MSC service thread 1-5) WFLYJCA0010: Unbound data source [java:jboss/datasources/ExampleDS]\n"
				+ "2020-07-14 13:25:21,016 INFO  [org.jboss.as.connector.deployment] (MSC service thread 1-8) WFLYJCA0011: Unbound JCA ConnectionFactory [java:/JmsXA]\n"
				+ "2020-07-14 13:25:21,019 INFO  [org.jboss.as.connector.deployers.jdbc] (MSC service thread 1-8) WFLYJCA0019: Stopped Driver service with driver-name = h2\n"
				+ "2020-07-14 13:25:21,053 INFO  [org.apache.activemq.artemis.ra] (ServerService Thread Pool -- 84) AMQ151003: resource adaptor stopped\n"
				+ "2020-07-14 13:25:21,148 INFO  [org.wildfly.extension.undertow] (MSC service thread 1-1) WFLYUT0008: Undertow HTTP listener default suspending\n"
				+ "2020-07-14 13:25:21,149 INFO  [org.wildfly.extension.undertow] (MSC service thread 1-1) WFLYUT0004: Undertow 1.3.28.Final-redhat-4 stopping\n"
				+ "2020-07-14 13:25:31,467 INFO  [org.jboss.as] (MSC service thread 1-2) WFLYSRV0050: JBoss EAP 7.0.6.GA (WildFly Core 2.1.15.Final-redhat-1) stopped in 10585ms";
		
		Set<String> ignoringUnavailableCiphers = sslService.extractListByRegexAndGroup(content, ignoringUnavaiableCipherRegex, 2);
		assertEquals(6, ignoringUnavailableCiphers.size());
		assertTrue(ignoringUnavailableCiphers.stream().anyMatch(cipher -> "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384".equals(cipher)));
		
	}
	
	@Test
	public void shouldExtractTrustStoreInfo() {
		
		String content = "2020-07-14 13:01:50,244 INFO  [stdout] (default task-1) Ignoring unavailable cipher suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA\n"
				+ "2020-07-14 13:01:50,244 INFO  [stdout] (default task-1) Ignoring unavailable cipher suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA\n"
				+ "2020-07-14 13:01:50,244 INFO  [stdout] (default task-1) Ignoring unavailable cipher suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n"
				+ "2020-07-14 13:01:50,496 INFO  [stdout] (default task-1) trustStore is: D:\\FOO\\Java\\jre\\lib\\security\\cacerts\n"
				+ "2020-07-14 13:01:50,496 INFO  [stdout] (default task-1) trustStore type is : jks\n"
				+ "2020-07-14 13:01:50,496 INFO  [stdout] (default task-1) trustStore provider is : \n"
				+ "2020-07-14 13:01:50,496 INFO  [stdout] (default task-1) init truststore\n"
				+ "2020-07-14 13:01:50,505 INFO  [stdout] (default task-1) adding as trusted cert:\n"
				+ "2020-07-14 13:01:50,506 INFO  [stdout] (default task-1)   Subject: CN=FOO FOO, O=BAR LTDA., C=BR\n"
				+ "2020-07-14 13:01:50,506 INFO  [stdout] (default task-1)   Issuer:  CN=FOO FOO, O=BAR LTDA., C=BR\n"
				+ "2020-07-14 13:01:50,509 INFO  [stdout] (default task-1)   Algorithm: RSA; Serial number: 0xxc35267\n"
				+ "2020-07-14 13:01:50,509 INFO  [stdout] (default task-1)   Valid from Mon Jun 21 09:30:00 IST 1999 until Mon Jun 22 09:30:00 IST 2020";

		TrustStoreInfo trustStoreInfo = sslService.extractTrustStoreInfo(content);
		
		assertEquals("D:\\FOO\\Java\\jre\\lib\\security\\cacerts", trustStoreInfo.path);
		assertEquals("jks", trustStoreInfo.type);
		assertEquals("", trustStoreInfo.provider);
		assertTrue(trustStoreInfo.lastTimemodified.equals(""));
	}
	
	@Test
	public void shouldExtractTrustedCertificatesWithOneCert() throws IOException {
		
		String content = "2020-07-14 13:25:21,357 INFO  [org.jboss.as.server.deployment] (MSC service thread 1-8) adding as trusted cert:\n"
				+ "2020-07-14 13:25:21,357 INFO  [org.jboss.as.server.deployment] (MSC service thread 1-8)   Subject: C=AA, O=BBB, OU=CCC, CN=DDD Root\n"
				+ "2020-07-14 13:25:21,357 INFO  [org.jboss.as.server.deployment] (MSC service thread 1-8)   Issuer:  C=AA, O=BBB, OU=CCC, CN=DDD Root\n"
				+ "2020-07-14 13:25:21,357 INFO  [org.jboss.as.server.deployment] (MSC service thread 1-8)   Algorithm: RSA; Serial number: 77777777777777777\n"
				+ "2020-07-14 13:25:21,357 INFO  [org.jboss.as.server.deployment] (MSC service thread 1-8)   Valid from Fri Apr 18 12:24:22 EDT 2008 until Thu Apr 13 12:24:22 EDT 2028 \n"
				+ "2020-07-14 13:25:31,467 INFO  [org.jboss.as] (MSC service thread 1-2) WFLYSRV0050: JBoss EAP 7.0.6.GA (WildFly Core 2.1.15.Final-redhat-1) stopped in 10585ms";

		List<TrustedCertificate> trustedCertificates = sslService.extractTrustedCertificates(content);
		
		assertEquals(1, trustedCertificates.size());
		assertEquals("C=AA, O=BBB, OU=CCC, CN=DDD Root", trustedCertificates.get(0).subject);
		assertEquals("C=AA, O=BBB, OU=CCC, CN=DDD Root", trustedCertificates.get(0).issuer);
		assertEquals("Fri Apr 18 12:24:22 EDT 2008", trustedCertificates.get(0).validFrom);
		assertEquals("Thu Apr 13 12:24:22 EDT 2028", trustedCertificates.get(0).validEnd);
	}
	
	@Test
	public void shouldExtractKeyStoreInfo() {
		
		String content = "2020-07-14 13:01:50,244 INFO  [stdout] (default task-1) Ignoring unavailable cipher suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA\n"
				+ "2020-07-14 13:01:50,244 INFO  [stdout] (default task-1) Ignoring unavailable cipher suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA\n"
				+ "2020-07-14 13:01:50,244 INFO  [stdout] (default task-1) Ignoring unavailable cipher suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n"
				+ "2020-07-14 13:01:50,931 INFO  [stdout] (default task-1) keyStore is : \n"
				+ "2020-07-14 13:01:50,931 INFO  [stdout] (default task-1) keyStore type is : jks\n"
				+ "2020-07-14 13:01:50,931 INFO  [stdout] (default task-1) keyStore provider is : \n"
				+ "2020-07-14 13:01:50,496 INFO  [stdout] (default task-1) init truststore\n"
				+ "2020-07-14 13:01:50,505 INFO  [stdout] (default task-1) adding as trusted cert:\n"
				+ "2020-07-14 13:01:50,506 INFO  [stdout] (default task-1)   Subject: CN=FOO FOO, O=BAR LTDA., C=BR\n"
				+ "2020-07-14 13:01:50,506 INFO  [stdout] (default task-1)   Issuer:  CN=FOO FOO, O=BAR LTDA., C=BR\n"
				+ "2020-07-14 13:01:50,509 INFO  [stdout] (default task-1)   Algorithm: RSA; Serial number: 0xxc35267\n"
				+ "2020-07-14 13:01:50,509 INFO  [stdout] (default task-1)   Valid from Mon Jun 21 09:30:00 IST 1999 until Mon Jun 22 09:30:00 IST 2020";

		KeyStoreInfo trustStoreInfo = sslService.extractKeystoreInfo(content);
		
		assertEquals("", trustStoreInfo.path);
		assertEquals("jks", trustStoreInfo.type);
		assertEquals("", trustStoreInfo.provider);
		
	}
	
	@Test
	public void shouldExtractUnsupportedCiphers() {
		
		String content = "2020-07-14 13:00:51,105 INFO  [org.jboss.modules] (main) JBoss Modules version 1.5.3.Final-redhat-1\n"
				+ "2020-07-14 13:00:51,797 INFO  [org.jboss.msc] (main) JBoss MSC version 1.2.7.SP1-redhat-1\n"
				+ "2020-07-14 13:00:52,072 INFO  [org.jboss.as] (MSC service thread 1-8) WFLYSRV0049: JBoss EAP 7.0.6.GA (WildFly Core 2.1.15.Final-redhat-1) starting\n"
				+ "2020-07-14 13:00:52,074 DEBUG [org.jboss.as.config] (MSC service thread 1-8) Configured system properties:"
				+ "2020-07-14 13:01:49,846 INFO  [stdout] (default task-1) Ignoring unavailable cipher suite: TLS_DH_anon_WITH_AES_256_CBC_SHA\n"
				+ "2020-07-14 13:01:49,891 INFO  [stdout] (default task-1) Ignoring unavailable cipher suite: TLS_DH_anon_WITH_AES_256_CBC_SHA256\n"
				+ "2020-07-14 13:01:49,891 INFO  [stdout] (default task-1) Ignoring unavailable cipher suite: TLS_RSA_WITH_AES_256_CBC_SHA\n"
				+ "2020-07-14 13:01:49,892 INFO  [stdout] (default task-1) Ignoring unavailable cipher suite: TLS_DHE_RSA_WITH_AES_256_GCM_SHA384\n"
				+ "2020-07-14 13:01:49,892 INFO  [stdout] (default task-1) Ignoring unavailable cipher suite: TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA\n"
				+ "2020-07-14 13:01:49,892 INFO  [stdout] (default task-1) Ignoring unavailable cipher suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\n"
				+ "2020-07-14 13:25:21,012 INFO  [org.wildfly.extension.undertow] (MSC service thread 1-6) WFLYUT0019: Host default-host stopping\n"
				+ "2020-07-14 13:04:03,983 INFO  [stdout] (default task-14) Ignoring unsupported cipher suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 for TLSv1\n"
				+ "2020-07-14 13:04:03,983 INFO  [stdout] (default task-14) Ignoring unsupported cipher suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 for TLSv1\n"
				+ "2020-07-14 13:04:03,983 INFO  [stdout] (default task-14) Ignoring unsupported cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA256 for TLSv1\n"
				+ "2020-07-14 13:04:03,983 INFO  [stdout] (default task-14) Ignoring unsupported cipher suite: TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 for TLSv1\n"
				+ "2020-07-14 13:25:21,014 INFO  [org.wildfly.extension.messaging-activemq] (MSC service thread 1-5) WFLYMSGAMQ0006: Unbound messaging object to jndi name java:jboss/DefaultJMSConnectionFactory\n"
				+ "2020-07-14 13:25:21,014 INFO  [org.jboss.as.connector.subsystems.datasources] (MSC service thread 1-5) WFLYJCA0010: Unbound data source [java:jboss/datasources/ExampleDS]\n"
				+ "2020-07-14 13:25:21,016 INFO  [org.jboss.as.connector.deployment] (MSC service thread 1-8) WFLYJCA0011: Unbound JCA ConnectionFactory [java:/JmsXA]\n"
				+ "2020-07-14 13:25:21,019 INFO  [org.jboss.as.connector.deployers.jdbc] (MSC service thread 1-8) WFLYJCA0019: Stopped Driver service with driver-name = h2\n"
				+ "2020-07-14 13:25:21,053 INFO  [org.apache.activemq.artemis.ra] (ServerService Thread Pool -- 84) AMQ151003: resource adaptor stopped\n"
				+ "2020-07-14 13:25:21,148 INFO  [org.wildfly.extension.undertow] (MSC service thread 1-1) WFLYUT0008: Undertow HTTP listener default suspending\n"
				+ "2020-07-14 13:25:21,149 INFO  [org.wildfly.extension.undertow] (MSC service thread 1-1) WFLYUT0004: Undertow 1.3.28.Final-redhat-4 stopping\n"
				+ "2020-07-14 13:25:31,467 INFO  [org.jboss.as] (MSC service thread 1-2) WFLYSRV0050: JBoss EAP 7.0.6.GA (WildFly Core 2.1.15.Final-redhat-1) stopped in 10585ms";
		
		Set<String> ignoringUnsupportedCiphers = sslService.extractListByRegexAndGroup(content, ignoringUnsuportedCipherRegex, 2);
		assertEquals(4, ignoringUnsupportedCiphers.size());
		assertTrue(ignoringUnsupportedCiphers.stream().anyMatch(cipher -> "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 for TLSv1".equals(cipher)));
		
	}
	

}
