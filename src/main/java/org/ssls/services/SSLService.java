package org.ssls.services;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.ssls.model.Chain;
import org.ssls.model.ClientHelloInfo;
import org.ssls.model.KeyStoreInfo;
import org.ssls.model.SSLHandshakeFile;
import org.ssls.model.ServerHelloInfo;
import org.ssls.model.TrustStoreInfo;
import org.ssls.model.TrustedCertificate;
import org.ssls.utils.RegexUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * 
 * @author pedro-hos
 *
 */

@ApplicationScoped
public class SSLService {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(SSLService.class);
	
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
	
	@ConfigProperty(name = "regex.server.hello.cipherSuite")
	String serverHelloCipherSuiteRegex;

	@ConfigProperty(name = "regex.server.hello.renegotiationInfo")
	String serverHelloRenegotiationInfoRegex;
	
	@ConfigProperty(name = "regex.chain.name")
	String chainNameRegex;

	@ConfigProperty(name = "regex.chain.version")
	String chainVersionRegex;

	@ConfigProperty(name = "regex.chain.subject")
	String chainSubjectRegex;
	
	@ConfigProperty(name = "regex.chain.signatureAlgorithm")
	String chainSignatureAlgorithmRegex;
	
	@ConfigProperty(name = "regex.chain.key")
	String chainKeyRegex;
	
	@ConfigProperty(name = "regex.chain.modulus")
	String chainModulusRegex;
	
	@ConfigProperty(name = "regex.chain.publicExponent")
	String chainPublicExponentRegex;
	
	@ConfigProperty(name = "regex.chain.issuer")
	String chainIssuerRegex;
	
	@ConfigProperty(name = "regex.chain.serialNumber")
	String chainSerialNumberRegex;
	
	@ConfigProperty(name = "regex.chain.certificateExtensions")
	String chainCertificateExtensionsQuantityRegex;
	
	@ConfigProperty(name = "regex.chain.validity")
	String chainValidityRegex;
	
	@ConfigProperty(name = "regex.chain.algorithm")
	String chainAlgorithmRegex;
	
	@ConfigProperty(name = "regex.chain.signature")
	String chainSignatureRegex;
	
	@Inject
	public FileService fileService;
	
	@Inject
	public JavaInfosService javaInfoService;
	
	/**
	 * 
	 * @param file
	 * @param output 
	 * @param isWeb 
	 * @param isFile 
	 */
	public void analyze(final String file, final String output, Boolean isFile, Boolean isWeb) {
		
		try {
			
			LOGGER.info("Analyzing file: " + file);
			SSLHandshakeFile infos = extractSSLHandshakeInfos(file).orElseThrow(); //TODO Criar uma exception
			
			if( isFile ) {
				
				LOGGER.info("Writing File: " + output);
				Objects.nonNull(output);
				
				fileService.writeFile(output, new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(infos));
				
			} else if(isWeb) {
				
			}
			
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
	protected Optional<SSLHandshakeFile> extractSSLHandshakeInfos(final String file) throws IOException {
		
		String content = fileService.readFile(file).orElseThrow();
		
		SSLHandshakeFile sslHandshakeFile = new SSLHandshakeFile();
		
		sslHandshakeFile.javaInfos = javaInfoService.extractJavaInfos(content);
		
		sslHandshakeFile.ignoringUnavailableCipher = RegexUtils.extractListByRegexAndGroup(content, ignoringUnavaiableCipherRegex, 2);
		sslHandshakeFile.ignoringUnsupportedCipher = RegexUtils.extractListByRegexAndGroup(content, ignoringUnsuportedCipherRegex, 2);
		sslHandshakeFile.ignoringDisabledCipher = RegexUtils.extractListByRegexAndGroup(content, ignoringDisabledCipherRegex, 2);
		
		sslHandshakeFile.trustStoreInfo = extractTrustStoreInfo(content);
		sslHandshakeFile.trustedCertificates = extractTrustedCertificates(content);
		
		sslHandshakeFile.keystoreInfo = extractKeystoreInfo(content);
		
		sslHandshakeFile.allowUnsafeRegotiation = Boolean.valueOf(RegexUtils.getByGroup(RegexUtils.getMatcher(allowUnsafeRenegotiationRegex, content), 2));
		sslHandshakeFile.allowLegacyHelloMessage = Boolean.valueOf(RegexUtils.getByGroup(RegexUtils.getMatcher(allowLegacyHelloMessageRegex, content), 2));
		sslHandshakeFile.isInitialHandshake = Boolean.valueOf(RegexUtils.getByGroup(RegexUtils.getMatcher(isInitialHandshakeRegex, content), 2));
		sslHandshakeFile.isSecureRegotiation = Boolean.valueOf(RegexUtils.getByGroup(RegexUtils.getMatcher(isSecureRenegotiationRegex, content), 2));
		
		int start = content.indexOf(clientHelloRegex);
		int end = content.indexOf(serverHelloRegex);
		
		if(start < end) {
			
			String helloContent = content.substring(start, end);
			sslHandshakeFile.clientHelloInfo = extractClientHelloInfo(helloContent);
			
		} else {
			LOGGER.info("Can't find Hello Content"); //TODO: rever isso! 
		}
		
		sslHandshakeFile.serverHelloInfo = getServerHelloInfo(getServerHelloContent(content).orElse("Not Found"));
		
		return Optional.ofNullable(sslHandshakeFile);
	}


	/**
	 * @param serverHelloContent
	 * @return
	 */
	protected ServerHelloInfo getServerHelloInfo(String content) {
		
		ServerHelloInfo serverHelloInfo = new ServerHelloInfo();
		
		serverHelloInfo.title = RegexUtils.getByGroup(RegexUtils.getMatcher(serverHelloTitleRegex, content), 1);
		serverHelloInfo.randomCookie = RegexUtils.getByGroup(RegexUtils.getMatcher(commonHelloRandomCookieRegex, content), 2);
		serverHelloInfo.sessionID = RegexUtils.getByGroup(RegexUtils.getMatcher(commonHelloSessionIdRegex, content), 2);
		serverHelloInfo.compressionMethods = replaceUnusualCharactersToList(RegexUtils.getByGroup(RegexUtils.getMatcher(commontHelloCompressionMethodsRegex, content), 2));
		serverHelloInfo.ecPointFormatsFormats = replaceUnusualCharactersToList(RegexUtils.getByGroup(RegexUtils.getMatcher(commonHelloEcPointFormatsFormatsRegex, content), 2));
		serverHelloInfo.cipherSuite = RegexUtils.getByGroup(RegexUtils.getMatcher(serverHelloCipherSuiteRegex, content), 2);
		serverHelloInfo.renegotiationInfo = RegexUtils.getByGroup(RegexUtils.getMatcher(serverHelloRenegotiationInfoRegex, content), 2);
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
		
	    Object[] matchers = RegexUtils.getMatcher(chainRegexStart, content).results().toArray();
	    
	    for (int i = 0; i < matchers.length; i++) {
	    	
			int startIndex = ((MatchResult) matchers[i]).start();
			
			if (i < matchers.length - 1) {
				
				int endIndex = ((MatchResult) matchers[i + 1]).start();
				allMatches.add(extractChainInfo(content.substring(startIndex, endIndex)));
				
			} else {
				allMatches.add(extractChainInfo(content.substring(startIndex)));
			}
			
		}
	    
		return allMatches;
	}

	/**
	 * @param substring
	 * @return
	 */
	protected Chain extractChainInfo(String content) {
		
		Chain chain = new Chain();
		
		chain.name = RegexUtils.getByGroup(RegexUtils.getMatcher(chainNameRegex, content), 1);
		chain.version = RegexUtils.getByGroup(RegexUtils.getMatcher(chainVersionRegex, content), 2);
		chain.subject = RegexUtils.getByGroup(RegexUtils.getMatcher(chainSubjectRegex, content), 2);
		chain.signatureAlgorithm = RegexUtils.getByGroup(RegexUtils.getMatcher(chainSignatureAlgorithmRegex, content), 2);
		
		Matcher matcher = RegexUtils.getMatcher(chainValidityRegex, content);
		
		if(matcher.find()) {
			chain.validity  = matcher.group(2).concat(matcher.group(5));
		}
		
		chain.key = RegexUtils.getByGroup(RegexUtils.getMatcher(chainKeyRegex, content), 2);
		chain.modulus = RegexUtils.getByGroup(RegexUtils.getMatcher(chainModulusRegex, content), 2);
		chain.publicExponent = RegexUtils.getByGroup(RegexUtils.getMatcher(chainPublicExponentRegex, content), 2);
		chain.issuer = RegexUtils.getByGroup(RegexUtils.getMatcher(chainIssuerRegex, content), 2);
		chain.serialNumber = RegexUtils.getByGroup(RegexUtils.getMatcher(chainSerialNumberRegex, content), 2);
		chain.certificateExtensionsQuantity = RegexUtils.getByGroup(RegexUtils.getMatcher(chainCertificateExtensionsQuantityRegex, content), 2);
		chain.algorithm = replaceUnusualCharactersToList(RegexUtils.getByGroup(RegexUtils.getMatcher(chainAlgorithmRegex, content), 2));
		chain.signature = RegexUtils.getByGroup(RegexUtils.getMatcher(chainSignatureRegex, content), 2);
		
		chain.certificateExtensions = extractCertificateExtensions(content, chain.certificateExtensionsQuantity);
		
		return chain;
	}

	/**
	 * @param content
	 * @param certificateExtensionsQuantity
	 * @return
	 */
	protected List<String> extractCertificateExtensions(String content, String quantity) {
		
		Objects.requireNonNull(quantity);
		Objects.requireNonNull(content);
		
		List<String> certificatesExtensions = new ArrayList<String>();
		
		int maxCertificatesExtensions = Integer.parseInt(quantity);
		
		for(int aux = 1; aux < maxCertificatesExtensions + 1; aux++) {
			
			int start = content.indexOf("[" + aux + "]:");
			int end = 0;
			
			if (aux == maxCertificatesExtensions) {
				
				Matcher matcher = RegexUtils.getMatcher(chainAlgorithmRegex, content);
				
				if(matcher.find()) {
					end = matcher.start(); //This could cause some problems
				}
				
			} else {
				end = content.indexOf("[" + (aux + 1) + "]");
			}
			
			if(start < end) {
				certificatesExtensions.add(content.substring(start, end).replaceAll("\n", "").trim());
			} else {
				LOGGER.info("Can't find Certificate Extensions");
			}
		}
		
		
		return certificatesExtensions;
	}

	/**
	 * @param content
	 */
	protected Optional<String> getServerHelloContent(final String content) {
		
		Optional<String> serverHelloContent = Optional.empty();
		
		if(!content.matches(serverHelloTitleRegex)) {
			LOGGER.info("File has not any Server Hello Info");
			return serverHelloContent;
		}
		
		int start = content.indexOf(serverHelloRegex);
		int end = 0;
		
	    Matcher matcher = RegexUtils.getMatcher("(\\s+])(.*\\n+)(.*\\*\\*\\*)", content);
	    
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
		
		clientHelloInfo.title = RegexUtils.getByGroup(RegexUtils.getMatcher(clientHelloTitleRegex, content), 1);
		clientHelloInfo.randomCookie = RegexUtils.getByGroup(RegexUtils.getMatcher(commonHelloRandomCookieRegex, content), 2);
		clientHelloInfo.sessionID = RegexUtils.getByGroup(RegexUtils.getMatcher(commonHelloSessionIdRegex, content), 2);
		clientHelloInfo.cipherSuites = replaceUnusualCharactersToList(RegexUtils.getByGroup(RegexUtils.getMatcher(clientHelloCipherSuitesRegex, content), 2));
		clientHelloInfo.compressionMethods = replaceUnusualCharactersToList(RegexUtils.getByGroup(RegexUtils.getMatcher(commontHelloCompressionMethodsRegex, content), 2));
		clientHelloInfo.ellipticCurvesCurveNames = replaceUnusualCharactersToList(RegexUtils.getByGroup(RegexUtils.getMatcher(clientHelloEllipticCurvesCurveNamesRegex, content), 2));
		clientHelloInfo.ecPointFormatsFormats = replaceUnusualCharactersToList(RegexUtils.getByGroup(RegexUtils.getMatcher(commonHelloEcPointFormatsFormatsRegex, content), 2));
		clientHelloInfo.signatureAlgorithms = replaceUnusualCharactersToList(RegexUtils.getByGroup(RegexUtils.getMatcher(clientHelloSignatureAlgorithmsRegex, content), 2));
		clientHelloInfo.serverName = RegexUtils.getByGroup(RegexUtils.getMatcher(clientHelloServerNameRegex, content), 2);
		clientHelloInfo.write = RegexUtils.getByGroup(RegexUtils.getMatcher(clientHelloWriteRegex, content), 2);
		clientHelloInfo.read = RegexUtils.getByGroup(RegexUtils.getMatcher(clientHelloReadRegex, content), 2);
		
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
		
		keyStoreInfo.path = RegexUtils.getByGroup(RegexUtils.getMatcher(keyStorePathRegex, content), 2);
		keyStoreInfo.type = RegexUtils.getByGroup(RegexUtils.getMatcher(keyStoreTypeRegex, content), 2);
		keyStoreInfo.provider = RegexUtils.getByGroup(RegexUtils.getMatcher(keyStoreProviderRegex, content), 2);
		
		return keyStoreInfo;
	}

	/**
	 * @param content
	 * @return
	 */
	protected List<TrustedCertificate> extractTrustedCertificates(String content) {
		
		List<TrustedCertificate> trustedCertificates = new ArrayList<>();
		
		Matcher m = RegexUtils.getMatcher(trustedCertificatesRegex, content);
		
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
		
		trustStoreInfo.path = RegexUtils.getByGroup(RegexUtils.getMatcher(trustStorePathRegex, content), 2);
		trustStoreInfo.type = RegexUtils.getByGroup(RegexUtils.getMatcher(trustStoreTypeRegex, content), 2);
		trustStoreInfo.provider = RegexUtils.getByGroup(RegexUtils.getMatcher(trustStoreProviderRegex, content), 2);
		trustStoreInfo.lastTimemodified = RegexUtils.getByGroup(RegexUtils.getMatcher(trustStoreLastModifiedRegex, content), 2);
		
		return trustStoreInfo;
	}

}
