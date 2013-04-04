package networksecurity.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.UUID;

import javax.crypto.SecretKey;

import networksecurity.common.ClientConfigReader;
import networksecurity.common.CryptoLibrary;
import networksecurity.common.HeaderHandler;
import networksecurity.common.MessageType;
import networksecurity.common.CryptoLibrary.EncryptionException;
import networksecurity.common.CryptoLibrary.HmacException;

public class ClientInfo {

	private String username;
	private String password;
	private UUID userId;
	private long userListTimeStamp;
	private ConnectionInfo connectionInfo;
	private PublicKey serverPublicKey;
	private KeyPair dhKeyPair;
	private SecretKey secretKey;
	private boolean isLoogedIn = false;
	
	/* Peers are those with whom current client had
	 * already set up a key 
	 */
	public HashMap<UUID,PeerInfo> peers = null;
	public HashMap<String, String> pendingMessages = new HashMap<String, String>();

	public ClientInfo(ClientConfigReader config) {
		this.peers = new HashMap<UUID, PeerInfo>();
		this.connectionInfo = new ConnectionInfo(config.getPort(), config.getServerAddress(), config.getServerPort());
		this.setServerPublicKey(getServerPublicKeyFromFile(config));
	}

	public PublicKey getServerPublicKeyFromFile(ClientConfigReader config) {
		try {
			return CryptoLibrary.readPublicKey(config.getPublicKeyLocation());
		} catch (Exception e) {
			System.out.println("Unable to read server's public key");
			throw new RuntimeException(e);
		}
	}

	/* setters */
	public void setUsername(String username) {
		this.username = username;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public void setUserId(UUID userId) {
		this.userId = userId;
	}

	public void setUserListTimestamp(long timestamp){
		this.userListTimeStamp = timestamp;
	}

	public void setServerPublicKey(PublicKey key) {
		this.serverPublicKey = key;
	}
	
	public void setdhKeyPair(KeyPair dhKeyPair){
		this.dhKeyPair = dhKeyPair;
	}
	
	public void setSecretKey(SecretKey key){
		this.secretKey = key;
	}
	
	public void setIsLoggedIn(boolean value){
		this.isLoogedIn = value;
	}

	/* getters */
	public String getUserName() {
		return this.username;
	}

	public String getPassword() {
		return this.password;
	}

	public UUID getUserId() {
		return this.userId;
	}
	
	public long getUserListTimestamp(){
		return this.userListTimeStamp;
	}
	
	public ConnectionInfo getConnectionInfo(){
		return this.connectionInfo;
	}

	public PublicKey getServerPublicKey() {
		return this.serverPublicKey;
	}
	
	public KeyPair getDHKeyPair(){
		return this.dhKeyPair;
	}
	
	public SecretKey getSecretKey(){
		return this.secretKey;
	}
	
	public boolean isLoggedIn(){
		return this.isLoogedIn;
	}

	/* methods */
	public void loginPrompt() throws Exception {
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		System.out.print("Username: ");
		try {
			this.setUsername(in.readLine());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.out.print("Password: ");
		try {
			this.setPassword(in.readLine());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		this.sendHelloToServer();
	}
	
	public void sendHelloToServer() throws Exception{
		try {
			this.connectionInfo.setClientSocket(new DatagramSocket(this
					.getConnectionInfo().getClientPort()));
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
		}

		String message = MessageType.CLIENT_SERVER_HELLO.createMessage("HELLO");
		byte[] messageBytes = null;
		try {
			messageBytes = message.getBytes(CryptoLibrary.CHARSET);
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
		}

		DatagramPacket packet = new DatagramPacket(messageBytes,
				messageBytes.length, this.getConnectionInfo().getServerIp(),
				this.getConnectionInfo().getServerPort());

		try {
			this.connectionInfo.getClientSocket().send(packet);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
		}
	}
	
	/* Send a message to given ip and port */
	public void sendMessage(String message, MessageType messageType,
			InetAddress destIp, int destPort) {
		message = messageType.createMessage(message);
		byte[] messageBytes;

		try {
			messageBytes = message.getBytes(CryptoLibrary.CHARSET);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return;
		}

		DatagramPacket packet = new DatagramPacket(messageBytes,
				messageBytes.length, destIp, destPort);

		try {
			this.connectionInfo.getClientSocket().send(packet);
		} catch (IOException e) {
			System.out.println("Error sending packet");
			e.printStackTrace();
			return;
		}
	}
	
	public void sendMessage(String peername, String message){
		PeerInfo peerInfo = this.getPeerByUserName(peername);

		if (peerInfo == null) {
			System.out.println(peername + "is not online anymore");
			return;
		}
		String[] messageParams = new String[2];
		messageParams[0] = this.getUserId().toString();
		
		String[] encryptedMessageParams = new String[]{message, String.valueOf(System.currentTimeMillis())};
		String encryptedMessage = null;
		try {
			encryptedMessage = CryptoLibrary.aesEncrypt(
				peerInfo.getSecretKey(),
				HeaderHandler.pack(encryptedMessageParams)
			);
		} catch (EncryptionException e) {
			System.out.println("Error encrypting message");
			e.printStackTrace();
			return;
		}
		
		String hMac;
		try {
			hMac = CryptoLibrary.hmacCreate(
				peerInfo.getSecretKey(), encryptedMessage
			);
		} catch (HmacException e) {
			System.out.println("Error generating hmac for message");
			e.printStackTrace();
			return;
		}
		
		messageParams[1] = hMac;
		
		sendMessage(HeaderHandler.pack(messageParams), MessageType.CLIENT_CLIENT_MESSAGE, peerInfo.getPeerIp(), peerInfo.getPeerPort());

	}
	
	public boolean isPeerExist(String username){
		if(this.peers == null){
			return false;
		}
		
		for (PeerInfo peer: this.peers.values()) {
			if (peer.getPeerUsername().equals(username)) {
				return true;
			}
		}
		return false;
	}
	
	public PeerInfo getPeerByUserName(String username){
		if(this.peers == null){
			return null;
		}
		
		for(PeerInfo peer: this.peers.values()){
			if(peer.getPeerUsername().equals(username)){
				return peer;
			}
		}
		
		return null;
	}
	
	public PeerInfo getPeer(UUID userId){
		if(this.peers == null){
			return null;
		}
		
		return this.peers.get(userId);
	}
}