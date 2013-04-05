package server;

import java.net.InetAddress;
import java.util.UUID;

import javax.crypto.SecretKey;

public class User {
	private String username;
	private String passwordHash;
	private UUID userId;
	private int userPort;
	private InetAddress userIp;
	private SecretKey sessionKey;
	
	/* Constructor */
	public User(String username, String validationHash) {
		this.username = username;
		this.passwordHash = validationHash;
	}
	
	/* setters */
	public void setUsername(String username){
		this.username = username;
	}
	
	public void setUserId(UUID userId){
		this.userId = userId;
	}
	
	public void setUserPort(int port){
		this.userPort = port;
	}
	
	public void setUserIp(InetAddress ip){
		this.userIp = ip;
	}
	
	public void setUserSessionKey(SecretKey key){
		this.sessionKey = key;
	}
	
	/* getters */
	public String getUsername(){
		return this.username;
	}
	
	public String getPasswordHash(){
		return this.passwordHash;
	}
	
	public UUID getUserId(){
		return this.userId;
	}
	
	public int getUserPort(){
		return this.userPort;
	}
	
	public InetAddress getUserIp(){
		return this.userIp;
	}
	
	public SecretKey getSessionKey(){
		return this.sessionKey;
	}
	
	public void destroySessionKey(){
		this.sessionKey = null;
	}
}
