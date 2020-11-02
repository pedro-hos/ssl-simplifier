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

	public List<String> ignoringUnavailableCipher;
	public TrustStoreInfo trustStoreInfo;
	public KeyStoreInfo keystoreInfo;
	public List<TrustedCertificate> trustedCertificates;
	
}
