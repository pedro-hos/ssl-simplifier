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
public class Chain implements Serializable {
	
	private static final long serialVersionUID = 2068240242212704717L;
	
	public String name;
	public String version;
	public String subject;
	public String signatureAlgorithm;
	public String key;
	public String modulus;
	public String publicExponent;
	public String validity;
	public String issuer;
	public String serialNumber;
	public String certificateExtensionsQuantity;
	public List<String> certificateExtensions;
	public List<String> algorithm;
	public String signature;
}
