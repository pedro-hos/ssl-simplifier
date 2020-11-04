/**
 * 
 */
package org.ssls.model;

import java.util.List;
import java.util.Set;

/**
 * @author pedro-hos
 *
 */
public class SSLHandshakeFile {

	public Boolean allowUnsafeRegotiation;
	public Boolean allowLegacyHelloMessage;
	public Boolean isInitialHandshake;
	public Boolean isSecureRegotiation;
	
	public ClientHelloInfo clientHelloInfo;
	
	public TrustStoreInfo trustStoreInfo;
	public KeyStoreInfo keystoreInfo;
	public Set<String> ignoringUnavailableCipher;
	public Set<String> ignoringUnsupportedCipher;
	public List<TrustedCertificate> trustedCertificates;
	
}
