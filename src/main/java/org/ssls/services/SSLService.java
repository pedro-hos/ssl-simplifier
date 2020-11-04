package org.ssls.services;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.enterprise.context.ApplicationScoped;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.ssls.SSLSMain;
import org.ssls.model.Chain;
import org.ssls.model.ClientHelloInfo;
import org.ssls.model.KeyStoreInfo;
import org.ssls.model.SSLHandshakeFile;
import org.ssls.model.ServerHelloInfo;
import org.ssls.model.TrustStoreInfo;
import org.ssls.model.TrustedCertificate;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * 
 * @author pedro-hos
 *
 */

@ApplicationScoped
public class SSLService {
	
	private static final String EMPTY_LINES_REGEX = "(?m)^[ \t]*\r?\n";

	private static final Logger LOGGER = LoggerFactory.getLogger(SSLSMain.class);
	
	@ConfigProperty(name = "regex.ignoring.unavailable.cipher")
	String ignoringUnavaiableCipherRegex;
	
	@ConfigProperty(name = "regex.ignoring.unsuported.cipher")
	String ignoringUnsuportedCipherRegex;
	
	@ConfigProperty(name = "regex.ignoring.disabled.cipher")
	String ignoringDisabledCipherRegex;
	
	@ConfigProperty(name = "regex.trustStore.path")
	String trustStorePathRegex;
	
	@ConfigProperty(name = "regex.trustStore.type")
	String trustStoreTypeRegex;
	
	@ConfigProperty(name = "regex.trustStore.provider")
	String trustStoreProviderRegex;
	
	@ConfigProperty(name = "regex.keyStore.path")
	String keyStorePathRegex;
	
	@ConfigProperty(name = "regex.keyStore.type")
	String keyStoreTypeRegex;
	
	@ConfigProperty(name = "regex.keyStore.provider")
	String keyStoreProviderRegex;
	
	@ConfigProperty(name = "regex.trustStore.lastTimemodified")
	String trustStoreLastModifiedRegex;
	
	@ConfigProperty(name = "regex.trusted.certificates")
	String trustedCertificatesRegex;
	
	@ConfigProperty(name = "regex.allow.unsafe.renegotiation")
	String allowUnsafeRenegotiationRegex;
	
	@ConfigProperty(name = "regex.allow.legacy.hello.message")
	String allowLegacyHelloMessageRegex;
	
	@ConfigProperty(name = "regex.is.initial.handshake")
	String isInitialHandshakeRegex;
	
	@ConfigProperty(name = "regex.is.secure.renegotiation")
	String isSecureRenegotiationRegex;
	
	@ConfigProperty(name = "regex.client.hello")
	String clientHelloRegex;
	      
	@ConfigProperty(name = "regex.client.hello.title")
	String clientHelloTitleRegex;
	
	@ConfigProperty(name = "regex.hello.common.randomCookie")
	String commonHelloRandomCookieRegex;
	
	@ConfigProperty(name = "regex.hello.common.sessionId")
	String commonHelloSessionIdRegex;
	
	@ConfigProperty(name = "regex.client.hello.cipherSuites")
	String clientHelloCipherSuitesRegex;
	
	@ConfigProperty(name = "regex.hello.common.compressionMethods")
	String commontHelloCompressionMethodsRegex;
	
	@ConfigProperty(name = "regex.client.hello.ellipticCurvesCurveNames")
	String clientHelloEllipticCurvesCurveNamesRegex;
	
	@ConfigProperty(name = "regex.hello.common.ecPointFormatsFormats")
	String commonHelloEcPointFormatsFormatsRegex;
	
	@ConfigProperty(name = "regex.client.hello.signatureAlgorithms")
	String clientHelloSignatureAlgorithmsRegex;
	
	@ConfigProperty(name = "regex.client.hello.serverName")
	String clientHelloServerNameRegex;
	
	@ConfigProperty(name = "regex.client.hello.write")
	String clientHelloWriteRegex;
	
	@ConfigProperty(name = "regex.client.hello.read")
	String clientHelloReadRegex;
	
	@ConfigProperty(name = "regex.server.hello")
	String serverHelloRegex;
	
	@ConfigProperty(name = "regex.server.hello.title")
	String serverHelloTitleRegex;
	
	@ConfigProperty(name = "output.file.name")
	String sslsFileNameOutput;

	@ConfigProperty(name = "regex.server.hello.cipherSuite")
	String serverHelloCipherSuiteRegex;

	@ConfigProperty(name = "regex.server.hello.renegotiationInfo")
	String serverHelloRenegotiationInfoRegex;

	/**
	 * 
	 * @param file
	 * @param output 
	 */
	public void analyze(final String file, final String output) {
		
		try {
			
			LOGGER.info("Analyzing file: " + file);
			SSLHandshakeFile infos = extractSSLHandshakeInfos(file).orElseThrow(); //TODO Criar uma exception
			
			LOGGER.info("Writing File: " + output);
			new ObjectMapper()
				.writerWithDefaultPrettyPrinter()
				.writeValue(new File(output + sslsFileNameOutput), infos);
			
		} catch (IOException e) {
			LOGGER.error(e.getMessage());
			e.printStackTrace();
		}
	}

	/**
	 * 
	 * @param file
	 * @return
	 * @throws IOException
	 */
	protected Optional<String> readFile(final String file) throws IOException {
		return Optional.of(String.join("\n", Files.readAllLines(Paths.get(file))).replaceAll(EMPTY_LINES_REGEX, ""));
	}

	/**
	 * 
	 * @param file
	 * @return
	 * @throws IOException
	 */
	protected Optional<SSLHandshakeFile> extractSSLHandshakeInfos(final String file) throws IOException {
		
		String content = readFile(file).orElseThrow();
		
		SSLHandshakeFile sslHandshakeFile = new SSLHandshakeFile();
		
		sslHandshakeFile.ignoringUnavailableCipher = extractListByRegexAndGroup(content, ignoringUnavaiableCipherRegex, 2);
		sslHandshakeFile.ignoringUnsupportedCipher = extractListByRegexAndGroup(content, ignoringUnsuportedCipherRegex, 2);
		sslHandshakeFile.ignoringDisabledCipher = extractListByRegexAndGroup(content, ignoringDisabledCipherRegex, 2);
		
		sslHandshakeFile.trustStoreInfo = extractTrustStoreInfo(content);
		sslHandshakeFile.trustedCertificates = extractTrustedCertificates(content);
		sslHandshakeFile.keystoreInfo = extractKeystoreInfo(content);
		
		sslHandshakeFile.allowUnsafeRegotiation = Boolean.valueOf(getByGroup(getMatcher(allowUnsafeRenegotiationRegex, content), 2));
		sslHandshakeFile.allowLegacyHelloMessage = Boolean.valueOf(getByGroup(getMatcher(allowLegacyHelloMessageRegex, content), 2));
		sslHandshakeFile.isInitialHandshake = Boolean.valueOf(getByGroup(getMatcher(isInitialHandshakeRegex, content), 2));
		sslHandshakeFile.isSecureRegotiation = Boolean.valueOf(getByGroup(getMatcher(isSecureRenegotiationRegex, content), 2));
		
		String helloContent = content.substring(content.indexOf(clientHelloRegex), content.indexOf(serverHelloRegex));
		sslHandshakeFile.clientHelloInfo = extractClientHelloInfo(helloContent);
		
		sslHandshakeFile.serverHelloInfo = getServerHelloInfo(getServerHelloContent(content).get());
		
		return Optional.ofNullable(sslHandshakeFile);
	}

	/**
	 * @param serverHelloContent
	 * @return
	 */
	protected ServerHelloInfo getServerHelloInfo(String content) {
		
		ServerHelloInfo serverHelloInfo = new ServerHelloInfo();
		
		serverHelloInfo.title = getByGroup(getMatcher(serverHelloTitleRegex, content), 1);
		serverHelloInfo.randomCookie = getByGroup(getMatcher(commonHelloRandomCookieRegex, content), 2);
		serverHelloInfo.sessionID = getByGroup(getMatcher(commonHelloSessionIdRegex, content), 2);
		serverHelloInfo.compressionMethods = replaceUnusualCharactersToList(getByGroup(getMatcher(commontHelloCompressionMethodsRegex, content), 2));
		serverHelloInfo.ecPointFormatsFormats = replaceUnusualCharactersToList(getByGroup(getMatcher(commonHelloEcPointFormatsFormatsRegex, content), 2));
		serverHelloInfo.cipherSuite = getByGroup(getMatcher(serverHelloCipherSuiteRegex, content), 2);
		serverHelloInfo.renegotiationInfo = getByGroup(getMatcher(serverHelloRenegotiationInfoRegex, content), 2);
		serverHelloInfo.chains = extractChains(content);
		
		return serverHelloInfo;
	}

	/**
	 * @param content
	 * @return
	 */
	protected Set<Chain> extractChains(String content) {
		
		Set<Chain> allMatches = new HashSet<Chain>();
		String chainRegexStart = "chain\\s*\\[\\d*\\]";
		
	    Object[] matchers = getMatcher(chainRegexStart, content).results().toArray();
	    
	    for (int i = 0; i < matchers.length; i++) {
	    	
	    	Chain chain = new Chain();
	    	
			int start2 = ((MatchResult) matchers[i]).start();
			
			if (i < matchers.length - 1) {
				
				int endIndex = ((MatchResult) matchers[i + 1]).start();
				chain.value = (content.substring(start2, endIndex));
				
			} else {
				chain.value = (content.substring(start2));
			}
			
			allMatches.add(chain);
		}
	    
		return allMatches;
	}

	/**
	 * @param content
	 */
	protected Optional<String> getServerHelloContent(final String content) {
		
		Optional<String> serverHelloContent = Optional.empty();
		
		int start = content.indexOf(serverHelloRegex);
		int end = 0;
		
	    Matcher matcher = getMatcher("(\\s+])(.*\\n+)(.*\\*\\*\\*)", content);
	    
	    if(matcher.find()){
	    	end = matcher.start(3);
	    	serverHelloContent = Optional.of(content.substring(start, end));
	    }
	    
		return serverHelloContent;
		
	}

	/**
	 * @param content
	 * @return
	 */
	protected ClientHelloInfo extractClientHelloInfo(String content) {
		
		ClientHelloInfo clientHelloInfo = new ClientHelloInfo();
		
		clientHelloInfo.title = getByGroup(getMatcher(clientHelloTitleRegex, content), 1);
		clientHelloInfo.randomCookie = getByGroup(getMatcher(commonHelloRandomCookieRegex, content), 2);
		clientHelloInfo.sessionID = getByGroup(getMatcher(commonHelloSessionIdRegex, content), 2);
		clientHelloInfo.cipherSuites = replaceUnusualCharactersToList(getByGroup(getMatcher(clientHelloCipherSuitesRegex, content), 2));
		clientHelloInfo.compressionMethods = replaceUnusualCharactersToList(getByGroup(getMatcher(commontHelloCompressionMethodsRegex, content), 2));
		clientHelloInfo.ellipticCurvesCurveNames = replaceUnusualCharactersToList(getByGroup(getMatcher(clientHelloEllipticCurvesCurveNamesRegex, content), 2));
		clientHelloInfo.ecPointFormatsFormats = replaceUnusualCharactersToList(getByGroup(getMatcher(commonHelloEcPointFormatsFormatsRegex, content), 2));
		clientHelloInfo.signatureAlgorithms = replaceUnusualCharactersToList(getByGroup(getMatcher(clientHelloSignatureAlgorithmsRegex, content), 2));
		clientHelloInfo.serverName = getByGroup(getMatcher(clientHelloServerNameRegex, content), 2);
		clientHelloInfo.write = getByGroup(getMatcher(clientHelloWriteRegex, content), 2);
		clientHelloInfo.read = getByGroup(getMatcher(clientHelloReadRegex, content), 2);
		
		return clientHelloInfo;
	}
	
	/**
	 * 
	 * @param value
	 * @return
	 */
	private List<String> replaceUnusualCharactersToList(final String value) {
		return Arrays.asList(value.replaceAll("[\\[\\]\\}\\{]", "").split(","));
	}

	/**
	 * @param content
	 * @return
	 */
	protected KeyStoreInfo extractKeystoreInfo(String content) {
		
		KeyStoreInfo keyStoreInfo = new KeyStoreInfo();
		
		keyStoreInfo.path = getByGroup(getMatcher(keyStorePathRegex, content), 2);
		keyStoreInfo.type = getByGroup(getMatcher(keyStoreTypeRegex, content), 2);
		keyStoreInfo.provider = getByGroup(getMatcher(keyStoreProviderRegex, content), 2);
		
		return keyStoreInfo;
	}

	/**
	 * @param content
	 * @return
	 */
	protected List<TrustedCertificate> extractTrustedCertificates(String content) {
		
		List<TrustedCertificate> trustedCertificates = new ArrayList<>();
		
		Matcher m = getMatcher(trustedCertificatesRegex, content);
		
		while(m.find()) {
			
			TrustedCertificate trustedCertificate = new TrustedCertificate();
			trustedCertificate.subject = m.group(4).trim();
			trustedCertificate.issuer = m.group(7).trim();
			trustedCertificate.algorithm = m.group(10).trim();
			trustedCertificate.validFrom = m.group(14).trim();
			trustedCertificate.validEnd = m.group(16).trim();
			
			trustedCertificates.add(trustedCertificate);
		}
		
		return trustedCertificates;
	}

	/**
	 * @param content
	 * @return
	 */
	protected TrustStoreInfo extractTrustStoreInfo(String content) {
		
		TrustStoreInfo trustStoreInfo = new TrustStoreInfo();
		
		trustStoreInfo.path = getByGroup(getMatcher(trustStorePathRegex, content), 2);
		trustStoreInfo.type = getByGroup(getMatcher(trustStoreTypeRegex, content), 2);
		trustStoreInfo.provider = getByGroup(getMatcher(trustStoreProviderRegex, content), 2);
		trustStoreInfo.lastTimemodified = getByGroup(getMatcher(trustStoreLastModifiedRegex, content), 2);
		
		return trustStoreInfo;
	}
	
	/**
	 * 
	 * @param content
	 * @param regex
	 * @param group
	 * @return
	 */
	protected Set<String> extractListByRegexAndGroup(final String content, final String regex, final int group) { 

		Set<String> allMatches = new HashSet<String>();
		
		Matcher m = getMatcher(regex, content);
		
		while(m.find()) {
			allMatches.add(m.group(group));
		}
		
		return allMatches;
	}
	
	private String getByGroup(final Matcher matcher, final int group) {
		return matcher.find() ? matcher.group(group) : "";
	}
	
	protected Matcher getMatcher(final String regex, final String value) {
		final Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
		return pattern.matcher(value);
	}
	

}
