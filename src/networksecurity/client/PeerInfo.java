package networksecurity.client;

import java.net.InetAddress;

import javax.crypto.SecretKey;

/* Peer is another client basically */
public class PeerInfo {
	private String username;
	private SecretKey tempSessionKey;
	private InetAddress peerIp;
	private int peerPort;
	private SecretKey secretKey;
	
	/* Constructor */
	public PeerInfo(String username, InetAddress peerIp, int peerPort, SecretKey key){
		this.username = username;
		this.peerIp = peerIp;
		this.peerPort = peerPort;
		this.tempSessionKey = key;
	}
	
	public void setSecretKey(SecretKey key){
		this.secretKey = key;
	}
	
	/* getters */
	public String getPeerUsername(){
		return this.username;
	}
	
	public SecretKey getTempSessionKey(){
		return this.tempSessionKey;
	}
	
	public InetAddress getPeerIp(){
		return this.peerIp;
	}
	
	public int getPeerPort(){
		return this.peerPort;
	}
	
	public SecretKey getSecretKey(){
		return this.secretKey;
	}
}
