package org.ssls;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.ssls.services.SSLService;

import picocli.CommandLine;

/**
 * 
 * @author pedro-hos
 *
 */

@CommandLine.Command(mixinStandardHelpOptions = true, name="SSL Simplifier" )
public class SSLSMain implements Runnable {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(SSLSMain.class);
	
	@CommandLine.Option(names = {"-f", "--file"}, description = "The file path with the SSL Handshake log")
	String file;
	
	SSLService sslService;

	@Override
	public void run() {
		LOGGER.info("Analyzing SSL Handshake Logs");
	}

}
