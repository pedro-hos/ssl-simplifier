/**
 * 
 */
package org.ssls.model;

import java.io.Serializable;

/**
 * @author pedro-hos
 *
 */
public class TrustedCertificate implements Serializable {
	
	private static final long serialVersionUID = 9189481909492250463L;
	
	public String subject;
	public String issuer;
	public String algorithm;
	public String validFrom;
	public String validEnd;

}
