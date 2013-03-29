package networksecurity.server;

import java.io.File;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.PrivateKey;
import java.util.HashMap;

import networksecurity.common.ConfigReader.ConfigReaderException;
import networksecurity.common.CryptoHelper;
import networksecurity.common.ServerConfigReader;

public class Server {

	public ServerInfo serverInfo = null;
	public final HashMap<String, User> users = new HashMap<String, User>();

	/**
	 * Entry point of the server
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		try {
			System.out.println("DEBUG:" + new File(".")
			.getCanonicalPath());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		String configFile = "src/networksecurity/resources/server.cfg";
		if (args.length == 1) {
			configFile = args[0];
		}

		final Server server = new Server(configFile);

		server.run();
	}

	/* Constructor */
	private Server(String configFile) {
		ServerConfigReader configReader;

		try {
			configReader = new ServerConfigReader(configFile);
		} catch (ConfigReaderException e) {
			System.out.println("Unable to read config file");
			throw new RuntimeException(e);
		}

		this.initializeServerInfo(configReader);
	}

	public void initializeServerInfo(ServerConfigReader serverConfig) {
		try{
			serverInfo = new ServerInfo(CryptoHelper.readPrivateKey(serverConfig.privateKeyLocation), serverConfig.port);
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
		
		for (final User user : serverConfig.users) {
			users.put(user.getUsername(), user);
		}
	}

	/**
	 * Listen on the configured port for incoming UDP packets.
	 */
	private void run() {
		byte[] buf = new byte[2048];
		boolean running = true;

		// Start Listening
		try {
			DatagramSocket socket = new DatagramSocket(this.serverInfo.getServerPort());
			DatagramPacket packet = new DatagramPacket(buf, buf.length);

			System.out.println("Server running...");

			while (running) {
				socket.receive(packet);
				String received = new String(packet.getData(), 0,
						packet.getLength(), CryptoHelper.CHARSET);

				MessageHandler handler = new MessageHandler(this, received,
						packet.getAddress(), packet.getPort(), socket);
				(new Thread(handler)).start();
			}

		} catch (Exception e) {
			System.out.print("Exception:" + e.toString());
		}
	}

}
