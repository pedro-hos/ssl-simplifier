package org.ssls.services;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.enterprise.context.ApplicationScoped;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.ssls.SSLSMain;
import org.ssls.model.SSLHandshakeFile;
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

	private static final Logger LOGGER = LoggerFactory.getLogger(SSLSMain.class);
	
	@ConfigProperty(name = "regex.ignoring.cipher")
	String ignoringUnavaiableCipherRegex;
	
	@ConfigProperty(name = "regex.trustStore.path")
	String trustStorePathRegex;
	
	@ConfigProperty(name = "regex.trustStore.type")
	String trustStoreTypeRegex;
	
	@ConfigProperty(name = "regex.trustStore.provider")
	String trustStoreProviderRegex;
	
	@ConfigProperty(name = "regex.trustStore.lastTimemodified")
	String trustStoreLastModifiedRegex;
	
	@ConfigProperty(name = "regex.trusted.certificates")
	String trustedCertificatesRegex;
	
	@ConfigProperty(name = "output.file.name")
	String sslsFileNameOutput;

	/**
	 * 
	 * @param file
	 * @param output 
	 */
	public void analyze(final String file, final String output) {
		
		try {
			
			LOGGER.info("Analyzing file: " + file);
			SSLHandshakeFile infos = extractSSLHandshakeInfos(file).orElseThrow();
			
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
		return Optional.of(String.join("\n", Files.readAllLines(Paths.get(file))));
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
		sslHandshakeFile.ignoringUnavailableCipher = extractIgnoringUnavailableCiphers(content);
		sslHandshakeFile.trustStoreInfo = extractTrustStoreInfo(content);
		sslHandshakeFile.trustedCertificates = extractTrustedCertificates(content);
		
		return Optional.ofNullable(sslHandshakeFile);
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
	 * @param content
	 * @return
	 */
	protected List<String> extractIgnoringUnavailableCiphers(final String content) {
		
		List<String> allMatches = new ArrayList<>();
		
		Matcher m = getMatcher(ignoringUnavaiableCipherRegex, content);
		
		while(m.find()) {
			allMatches.add(m.group(2));
		}
		
		return allMatches;
	}
	
	private String getByGroup(final Matcher matcher, final int group) {
		return matcher.find() ? matcher.group(group) : "";
	}
	
	private Matcher getMatcher(final String regex, final String value) {
		final Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
		return pattern.matcher(value);
	}
	

}
