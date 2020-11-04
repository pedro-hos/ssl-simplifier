/**
 * 
 */
package org.ssls.model;

import java.util.Set;

/**
 * @author pedro-hos
 *
 */
public class ServerHelloInfo extends CommonHelloInfo {

	private static final long serialVersionUID = -630989926144698593L;
	
	public String cipherSuite;
	public String renegotiationInfo;
	public Set<Chain> chains;

}
