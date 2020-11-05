package org.ssls;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.ssls.services.SSLService;

import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.QuarkusApplication;
import io.quarkus.runtime.annotations.QuarkusMain;
import picocli.CommandLine;

/**
 * 
 * @author pedro-hos
 *
 */

@QuarkusMain
@CommandLine.Command(mixinStandardHelpOptions = true, name="SSL Simplifier" )
public class SSLSMain implements Runnable, QuarkusApplication {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(SSLSMain.class);
	
	@CommandLine.Option(names = {"-f", "--file"}, description = "The file path with the SSL Handshake log", required = true)
	String file;
	
	@CommandLine.Option(names = {"-o", "--output"}, description = "The output file path that we'll save the analyze file")
	String output;
	
	@CommandLine.Option(names = {"-iw", "--isweb"}, description = "This option shows the report by web page at http://localhost:8080/", defaultValue = "false")
	Boolean isWeb;
	
	@CommandLine.Option(names = {"-if", "--isfile"}, description = "This option shows the report by json file at the 'output' parameter", defaultValue = "false")
	Boolean isFile;
	
	@Inject
	SSLService sslService;
	
	@Inject
    CommandLine.IFactory factory;

	@Override
	public void run() {
		
		LOGGER.info("Analyzing SSL Handshake Logs");
		sslService.analyze(file, output, isFile, isWeb);
		
		if(isWeb) {
			Quarkus.waitForExit();
		}
		
	}

	@Override
	public int run(String... args) throws Exception {
		return new CommandLine(this, factory).execute(args);
	}

}
