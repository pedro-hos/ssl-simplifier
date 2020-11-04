/**
 * 
 */
package org.ssls.model;

import java.util.List;

/**
 * @author pedro-hos
 *
 */
public class ClientHelloInfo {
	
	public String title;
	public String randomCookie;
	public String sessionID;
	public List<String> cipherSuites;
	public List<String> compressionMethods;
	public List<String> ellipticCurvesCurveNames;
	public List<String> ecPointFormatsFormats;
	public List<String> signatureAlgorithms;
	public String serverName;
	public String write;
	public String read;
	

}
