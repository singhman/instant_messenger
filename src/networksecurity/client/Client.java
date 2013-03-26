package networksecurity.client;

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.PublicKey;

import networksecurity.common.*;
import networksecurity.common.ConfigReader.ConfigReaderException;

public class Client {

	private final int port;
	private final int serverPort;
	private final InetAddress serverIp;
	private String username;
	private String validationHash;
	private PublicKey serverPublicKey;
	private ClientListener clientListener;
	private DatagramSocket outgoingSocket;
	
	/**
	 * @param configFile Location of the config file to parse.
	 */
	private Client(String configFile) {
		ClientConfigReader config;
		
		try {
			config = new ClientConfigReader(configFile);
		} catch (ConfigReaderException e) {
			System.out.println("Unable to read config file");
			throw new RuntimeException(e);
		}
		
		try {
			serverPublicKey = Crypto.readPublicKey(config.getPublicKeyLocation());
		} catch (Exception e) {
			System.out.println("Unable to read server's public key");
			throw new RuntimeException(e);
		}
		
		
		port = config.getPort();
		serverPort = config.getServerPort();
		serverIp = config.getServerAddress();
		
		this.clientListener = new ClientListener(this, port);
		(new Thread(this.clientListener)).start();
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String configFile = "resources/client.cfg";
		if (args.length == 1) {
			configFile = args[0];
		}
		
		Client client = new Client(configFile);
		
		try {
			client.login();
		} catch (Exception e) {
			System.out.println("Unable to send connection to server");
			e.printStackTrace();
			return;
		}
		
		client.run();
	}
	
	private void login(){
		
	}
	
	private void run(){
		
	}

}
