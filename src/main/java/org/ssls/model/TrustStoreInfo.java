/**
 * 
 */
package org.ssls.model;

import java.io.Serializable;

/**
 * @author pedro-hos
 *
 */
public class TrustStoreInfo implements Serializable {
	
	private static final long serialVersionUID = 3100231333327189305L;
	
	public String path;
	public String type;
	public String provider;
	public String lastTimemodified;

}
