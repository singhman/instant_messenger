package networksecurity.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.UUID;

import javax.crypto.SecretKey;

import networksecurity.common.ClientConfigReader;
import networksecurity.common.CryptoHelper;

public class ClientInfo {

	private String username;
	private String password;
	private UUID userId;
	private int clientPort;
	private InetAddress clientIp;
	private Key clientServerKey;
	private Key clientClientKey;
	private DatagramSocket clientSocket;
	private int serverPort;
	private InetAddress serverIp;
	private PublicKey serverPublicKey;
	private CommandHandler commandHandler;
	private KeyPair dhKeyPair;
	private SecretKey secretKey;

	public ClientInfo(ClientConfigReader config) {
		this.setClientPort(config.getPort());
		this.setServerPort(config.getServerPort());
		this.setServerIp(config.getServerAddress());
		this.setServerPublicKey(getServerPublicKeyFromFile(config));
	}

	public PublicKey getServerPublicKeyFromFile(ClientConfigReader config) {
		try {
			return CryptoHelper.readPublicKey(config.getPublicKeyLocation());
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

	public void setClientPort(int port) {
		this.clientPort = port;
	}

	public void setClientIp(InetAddress ipAddress) {
		this.clientIp = ipAddress;
	}

	public void setClientServerKey(Key clientServerKey) {
		this.clientServerKey = clientServerKey;
	}

	public void setClientClientKey(Key clientclientKey) {
		this.clientClientKey = clientclientKey;
	}

	public void setClientSocket(DatagramSocket clientSocket) {
		this.clientSocket = clientSocket;
	}

	public void setServerPort(int port) {
		this.serverPort = port;
	}

	public void setServerIp(InetAddress ipAddress) {
		this.serverIp = ipAddress;
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

	public int getClientPort() {
		return this.clientPort;
	}

	public InetAddress getClientIp() {
		return this.clientIp;
	}

	public Key getClientServerKey() {
		return this.clientServerKey;
	}

	public Key getClientClientKey() {
		return this.clientClientKey;
	}

	public DatagramSocket getClientSocket() {
		return this.clientSocket;
	}

	public int getServerPort() {
		return this.serverPort;
	}

	public InetAddress getServerIp() {
		return this.serverIp;
	}

	public PublicKey getServerPublicKey() {
		return this.serverPublicKey;
	}
	
	public KeyPair getdhKeyPair(){
		return this.dhKeyPair;
	}
	
	public SecretKey getSecretKey(){
		return this.secretKey;
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
		
		this.commandHandler = new CommandHandler(this, this.getClientSocket(), this.getServerIp(), this.getServerPort());
		(new Thread(this.commandHandler)).start();
	}
}