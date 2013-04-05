package server;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.UUID;
import java.util.Iterator;

import common.CryptoLibrary;
import common.ConfigReader.ConfigReaderException;


public class Server {

	public ServerInfo serverInfo = null;
	public final HashMap<String, User> registeredUsers = new HashMap<String, User>();
	public final HashMap<UUID, User> onlineUsers = new HashMap<UUID, User>();

	/**
	 * Entry point of the server
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

		String configFile = "src/resources/server.cfg";
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
			e.printStackTrace();
			return;
		}

		this.initializeServerInfo(configReader);
	}

	public void initializeServerInfo(ServerConfigReader serverConfig) {
		try {
			serverInfo = new ServerInfo(
					CryptoLibrary
							.readPrivateKey(serverConfig.privateKeyLocation),
					serverConfig.port);
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}

		for (final User user : serverConfig.users) {
			registeredUsers.put(user.getUsername(), user);
		}
	}

	/*
	 * Listen on the configured port for incoming UDP packets.
	 */
	private void run() {
		byte[] buf = new byte[2048];
		boolean running = true;
		DatagramSocket socket = null;
		
		// Start Listening
		try {
			socket = new DatagramSocket(
					this.serverInfo.getServerPort());
			DatagramPacket packet = new DatagramPacket(buf, buf.length);

			System.out.println("Server running...");

			while (running) {
				socket.receive(packet);
				String received = new String(packet.getData(), 0,
						packet.getLength(), CryptoLibrary.CHARSET);

				MessageHandler handler = new MessageHandler(this, received,
						packet.getAddress(), packet.getPort(), socket);
				(new Thread(handler)).start();
			}

		} catch (Exception e) {
			System.out.print("Exception:" + e.toString());
		} finally {
			if(!socket.isClosed())
			socket.close();
		}
	}

	public User getUser(String userName) {
		if(this.registeredUsers == null){
			return null;
		}
		
		return this.registeredUsers.get(userName);
	}

	public void loginUser(UUID userId, User user) {
		if(!this.onlineUsers.containsKey(userId)){
			this.onlineUsers.put(userId, user);
		}
	}

	public void logoutUser(UUID userId) {
		if(this.onlineUsers.containsKey(userId)){
			this.onlineUsers.remove(userId);
		}
	}
	
	public void destroySessionKey(UUID userId){
		User user = this.onlineUsers.get(userId);
		if(user != null){
			user.destroySessionKey();
			return;
		}
	}

	public boolean isOnline(UUID userId) {
		return this.onlineUsers.containsKey(userId);
	}

	public boolean isRegistered(String userName) {
		if(this.registeredUsers == null){
			return false;
		}
		return this.registeredUsers.containsKey(userName);
	}

	public boolean isOnline(String username) {
		if(this.onlineUsers == null){
			return false;
		}
		
		for (User user : this.onlineUsers.values()) {
			if (user.getUsername().equals(username)) {
				return true;
			}
		}
		return false;
	}

	public boolean isAlreadyOnline(int port, InetAddress ip) {
		if(this.onlineUsers == null){
			return false;
		}
		
		for (User user : this.onlineUsers.values()) {
			if (user.getUserPort() == port && user.getUserIp().equals(ip)) {
				return true;
			}
		}
		return false;
	}

	public User getRegisteredUserByUUID(UUID userId) {
		if(this.registeredUsers == null){
			return null;
		}
		
		for (User user : this.registeredUsers.values()) {
			if (user.getUserId() != null) {
				if (user.getUserId().equals(userId)) {
					return user;
				}
			}
		}
		return null;
	}
	
	public User getOnlineUser(String userName){
		if(this.onlineUsers == null){
			return null;
		}
		
		for (User user : this.onlineUsers.values()) {
			if (user.getUsername().equals(userName)) {
				return user;
			}
		}
		
		return null;
	}

	public User getOnlineUserByUUID(UUID userId) {
		if(this.onlineUsers == null){
			return null;
		}
		
		return this.onlineUsers.get(userId);
	}

	public String getUserList() {
		final StringBuilder builder = new StringBuilder();
		final ArrayList<String> usernames = new ArrayList<String>();

		for (User user : onlineUsers.values()) {
			usernames.add(user.getUsername());
		}

		Collections.sort(usernames);
		final Iterator<String> usernamesIterator = usernames.iterator();

		while (usernamesIterator.hasNext()) {
			builder.append(usernamesIterator.next());

			if (usernamesIterator.hasNext()) {
				builder.append(",");
			}
		}

		return builder.toString();
	}
}
