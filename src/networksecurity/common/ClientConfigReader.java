package networksecurity.common;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Config file reader for the client.
 */
public class ClientConfigReader extends ConfigReader {
	
	/**
	 * The port this client should listen on.
	 */
	int port;
	
	/**
	 * The port the server listens on.
	 */
	int serverPort;
	
	/**
	 * The address of the server.
	 */
	InetAddress serverAddress;
	
	/**
	 * The location of the server's public key.
	 */
	String publicKeyLocation;
	
	/**
	 * Parse the config file in the given location.
	 * 
	 * @param filename The location of the config file to parse.
	 * 
	 * @throws ConfigReaderException Thrown for all errors.
	 */
	public ClientConfigReader(String filename)
			throws ConfigReaderException 
	{
		super.parseFile(new ConfigEntryAction[] {
			new PortEntry(),
			new ServerPortEntry(),
			new ServerAddressEntry(),
			new PublicKeyEntry()
		}, filename);
	}

	public int getPort(){
		return this.port;
	}
	
	public int getServerPort(){
		return this.serverPort;
	}
	
	public InetAddress getServerAddress(){
		return this.serverAddress;
	}
	
	public String getPublicKeyLocation(){
		return this.publicKeyLocation;
	}
	
	/**
	 * The config entry action for the client's port.
	 */
	private class PortEntry extends ConfigEntryAction {
		public PortEntry() { super("port"); }

		/* (non-Javadoc)
		 * @see common.AbstractConfigReader.ConfigEntryAction#performAction(java.lang.String)
		 */
		@Override
		public void performAction(String value) {
			port = Integer.valueOf(value);		
		}
	}
	
	/**
	 * The config entry action for the server's port.
	 */
	private class ServerPortEntry extends ConfigEntryAction {
		public ServerPortEntry() { super("serverPort"); }

		/* (non-Javadoc)
		 * @see common.AbstractConfigReader.ConfigEntryAction#performAction(java.lang.String)
		 */
		@Override
		public void performAction(String value) {
			serverPort = Integer.valueOf(value);		
		}
	}
	/**
	 * The config entry action for the server's address.
	 */
	private class ServerAddressEntry extends ConfigEntryAction {
		public ServerAddressEntry() { super("serverAddress"); }

		/* (non-Javadoc)
		 * @see common.AbstractConfigReader.ConfigEntryAction#performAction(java.lang.String)
		 */
		@Override
		public void performAction(String value) throws ConfigReaderException {
			try {
				serverAddress = InetAddress.getByName(value);
			} catch (UnknownHostException e) {
				throw new ConfigReaderException(e);
			}		
		}
	}
	
	/**
	 * The config entry action for the server's public key location.
	 */
	private class PublicKeyEntry extends ConfigEntryAction {
		public PublicKeyEntry() { super("publicKey"); }

		/* (non-Javadoc)
		 * @see common.AbstractConfigReader.ConfigEntryAction#performAction(java.lang.String)
		 */
		@Override
		public void performAction(String value) {
			publicKeyLocation = value;
		}
	}
}
