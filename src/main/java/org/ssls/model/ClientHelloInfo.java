/**
 * 
 */
package org.ssls.model;

import java.util.List;

/**
 * @author pedro-hos
 *
 */
public class ClientHelloInfo extends CommonHelloInfo {
	
	private static final long serialVersionUID = 6476655989393256485L;
	
	public String serverName;
	public List<String> signatureAlgorithms;
	public List<String> ellipticCurvesCurveNames;
	public List<String> cipherSuites;
	public String write;
	public String read;
	

}
