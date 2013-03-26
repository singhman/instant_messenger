package networksecurity.server;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.PrivateKey;
import java.util.HashMap;

import networksecurity.common.ConfigReader.ConfigReaderException;
import networksecurity.common.Crypto;
import networksecurity.common.ServerConfigReader;

public class Server {

	/* Server Info */
	private int serverPort;
	private PrivateKey privateKey;
	private final HashMap<String, User> users = new HashMap<String, User>();

	/**
	 * Entry point of the server
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

		String configFile = "resources/server.cfg";
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
		this.serverPort = serverConfig.port;

		for (final User user : serverConfig.users) {
			users.put(user.getUsername(), user);
		}

		try {
			this.privateKey = Crypto
					.readPrivateKey(serverConfig.privateKeyLocation);
		} catch (Exception e) {
			throw new RuntimeException(e);
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
			DatagramSocket socket = new DatagramSocket(this.serverPort);
			DatagramPacket packet = new DatagramPacket(buf, buf.length);

			System.out.println("Server running...");

			while (running) {
				socket.receive(packet);
				String received = new String(packet.getData(), 0,
						packet.getLength(), Crypto.CHARSET);

//				MessageHandler handler = new MessageHandler(this, received,
//						packet.getAddress(), packet.getPort(), socket);
//				(new Thread(handler)).start();
			}

		} catch (Exception e) {
			System.out.print("Exception:" + e.toString());
		}
	}

}
