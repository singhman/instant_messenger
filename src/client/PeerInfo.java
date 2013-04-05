package client;

import java.net.InetAddress;
import java.util.UUID;

import javax.crypto.SecretKey;

/* Peer is another client basically */
public class PeerInfo {
	private String username;
	private SecretKey tempSessionKey;
	private InetAddress peerIp;
	private int peerPort;
	private UUID peerUserId;
	private SecretKey secretKey;
	private String pendingMessage;
	
	/* Constructor */
	public PeerInfo(String username, InetAddress peerIp, int peerPort,UUID userId, SecretKey tempKey){
		this.username = username;
		this.peerIp = peerIp;
		this.peerPort = peerPort;
		this.tempSessionKey = tempKey;
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
	
	public UUID getPeerUserId(){
		return this.peerUserId;
	}
	
	public SecretKey getSecretKey(){
		return this.secretKey;
	}
	
	public String getPendingMessage(){
		return this.pendingMessage;
	}
}
