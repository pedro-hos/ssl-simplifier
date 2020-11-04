/**
 * 
 */
package org.ssls.model;

import java.io.Serializable;
import java.util.List;

/**
 * @author pedro-hos
 *
 */
public class CommonHelloInfo implements Serializable {
	
	private static final long serialVersionUID = 5574881734453885192L;
	
	public String title;
	public String randomCookie;
	public String sessionID;
	public List<String> compressionMethods;
	public List<String> ecPointFormatsFormats;
	

}
