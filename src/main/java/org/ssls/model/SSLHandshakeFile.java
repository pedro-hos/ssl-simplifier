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
	public List<TrustedCertificate> trustedCertificates;
	
}
