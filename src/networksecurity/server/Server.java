package networksecurity.server;

import java.io.File;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.UUID;
import java.util.Iterator;

import networksecurity.common.ConfigReader.ConfigReaderException;
import networksecurity.common.CryptoLibrary;
import networksecurity.common.ServerConfigReader;

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
			serverInfo = new ServerInfo(CryptoLibrary.readPrivateKey(serverConfig.privateKeyLocation), serverConfig.port);
		}
		catch (Exception e) {
			throw new RuntimeException(e);
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

		// Start Listening
		try {
			DatagramSocket socket = new DatagramSocket(this.serverInfo.getServerPort());
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
		}
	}

	public User getUser(String userName){
		return this.registeredUsers.get(userName);
	}
	
	public void loginUser(UUID userId, User user){
		this.onlineUsers.put(userId,user); 
	}
	
	public void logoutUser(UUID userId){
		this.onlineUsers.remove(userId);
	}
	
	public boolean isOnline(UUID userId){
		return this.onlineUsers.containsKey(userId);
	}
	
	public boolean isRegistered(String userName){
		return this.registeredUsers.containsKey(userName);
	}
	
	public boolean isAlreadyOnline(String username){
		for (User user : this.onlineUsers.values()) {
			if(user.getUsername().equals(username)){
				return true;
			}
		}
		return false;
	}
	
	public boolean isAlreadyOnlineByPort(int port){
		for (User user : onlineUsers.values()) {
			if(user.getUserPort() == port){
				return true;
			}
		}
		return false;
	}
	
	public User getRegisteredUserByUUID(UUID userId){
		for (User user : registeredUsers.values()) {
			if(user.getUserId().equals(userId)){
				return user;
			}
		}
		return null;
	}
	
	public User getOnlineUserByUUID(UUID userId){
		return this.onlineUsers.get(userId);
	}
	
	public String getUserList(){
		final StringBuilder builder = new StringBuilder();		
		final ArrayList<String> usernames = new ArrayList<String>();
		
		for (User user : onlineUsers.values()) {
			usernames.add(user.getUsername());
		}
		
		Collections.sort(usernames);
		final Iterator<String> usernamesIterator = usernames.iterator();
		
		while(usernamesIterator.hasNext()) {
			builder.append(usernamesIterator.next());
			
			if (usernamesIterator.hasNext()) {
				builder.append(",");
			}
		}
		
		return builder.toString();
	}
}
