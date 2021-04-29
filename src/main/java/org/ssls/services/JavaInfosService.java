/**
 * 
 */
package org.ssls.services;

import javax.enterprise.context.ApplicationScoped;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.ssls.model.JavaInfos;
import org.ssls.utils.RegexUtils;

/**
 * @author pedro-hos@outlook.com
 *
 */
@ApplicationScoped
public class JavaInfosService {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(JavaInfosService.class);
	
	@ConfigProperty(name = "regex.java.version")
	String javaVersionRegex;
	
	@ConfigProperty(name = "regex.java.name")
	String javaNameRegex;
	
	@ConfigProperty(name = "regex.java.vendor")
	String javaVendorRegex;
	
	/**
	 * @param content
	 * @return
	 */
	protected JavaInfos extractJavaInfos(String content) {
		LOGGER.info("Extracting JVM infos");
		
		JavaInfos java = new JavaInfos();
		java.version = RegexUtils.getByGroup(RegexUtils.getMatcher(javaVersionRegex, content), 2);
		java.name = RegexUtils.getByGroup(RegexUtils.getMatcher(javaNameRegex, content), 2);
		java.vendor = RegexUtils.getByGroup(RegexUtils.getMatcher(javaVendorRegex, content), 2);
		
		return java;
	}

}
