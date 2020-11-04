/**
 * 
 */
package org.ssls.model;

import java.io.Serializable;
import java.util.List;
import java.util.Set;

/**
 * @author pedro-hos
 *
 */
public class SSLHandshakeFile implements Serializable {

	private static final long serialVersionUID = -2569123227530935336L;
	
	public Boolean allowUnsafeRegotiation;
	public Boolean allowLegacyHelloMessage;
	public Boolean isInitialHandshake;
	public Boolean isSecureRegotiation;
	
	public ClientHelloInfo clientHelloInfo;
	public ServerHelloInfo serverHelloInfo;
	
	public TrustStoreInfo trustStoreInfo;
	public KeyStoreInfo keystoreInfo;
	public Set<String> ignoringUnavailableCipher;
	public Set<String> ignoringUnsupportedCipher;
	public Set<String> ignoringDisabledCipher;
	
	public List<TrustedCertificate> trustedCertificates;
	
}
