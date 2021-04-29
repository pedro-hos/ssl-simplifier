/**
 * 
 */
package org.ssls.services;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Optional;

import javax.enterprise.context.ApplicationScoped;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author pedro-hos@outlook.com
 *
 */
@ApplicationScoped
public class FileService {

	private static final Logger LOGGER = LoggerFactory.getLogger(FileService.class);

	private static final String EMPTY_LINES_REGEX = "(?m)^[ \t]*\r?\n";
	private static final String JBOSS_LOG_PREFIX = "\\d{4}-\\d{2}-\\d{2}\\s+\\d{2}:\\d{2}:\\d{2},\\d{3}\\s+\\w{3,7}\\s+\\[.*?\\]\\s+\\(.*\\)";
	
	@ConfigProperty(name = "output.file.name")
	String sslsFileNameOutput;
	
	/**
	 * 
	 * @param file
	 * @return
	 * @throws IOException
	 */
	protected Optional<String> readFile(final String file) throws IOException {
		LOGGER.info("Reading File: " + file);
		return Optional.of(String.join("\n", Files.readAllLines(Paths.get(file))).replaceAll(EMPTY_LINES_REGEX, "").replaceAll(JBOSS_LOG_PREFIX, ""));
	}
	
	
	protected void writeFile(final String output, final String value) throws IOException {
		LOGGER.info("Saving output at: " + output);
		Files.writeString(Paths.get(output + sslsFileNameOutput), value, StandardOpenOption.CREATE);
	}

}
