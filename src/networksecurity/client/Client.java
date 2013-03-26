package networksecurity.client;

import networksecurity.common.*;
import networksecurity.common.ConfigReader.ConfigReaderException;

public class Client {
	
	/* starting point of the client */
	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		String configFile = "resources/client.cfg";
		if (args.length == 1) {
			configFile = args[0];
		}

		ClientConfigReader configReader;
		try {
			configReader = new ClientConfigReader(configFile);
		} catch (ConfigReaderException e) {
			System.out.println("Unable to read config file");
			throw new RuntimeException(e);
		}
		
		ClientInfo clientInfo = new ClientInfo(configReader);
		clientInfo.loginPrompt();
	}

}
