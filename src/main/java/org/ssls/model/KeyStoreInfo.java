/**
 * 
 */
package org.ssls.model;

import java.io.Serializable;

/**
 * @author pedro-hos
 *
 */
public class KeyStoreInfo implements Serializable {
	
	private static final long serialVersionUID = 5032364659669672982L;
	
	public String path;
	public String type;
	public String provider;

}
