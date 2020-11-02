/**
 * 
 */
package org.ssls.model;

import java.util.List;

/**
 * @author pedro-hos
 *
 */
public class SSLHandshakeFile {

	public TrustStoreInfo trustStoreInfo;
	public KeyStoreInfo keystoreInfo;
	public List<String> ignoringUnavailableCipher;
	public List<TrustedCertificate> trustedCertificates;
	
}
