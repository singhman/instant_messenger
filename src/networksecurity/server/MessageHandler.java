package networksecurity.server;

import java.net.DatagramSocket;
import java.net.InetAddress;

import networksecurity.common.MessageType;
import networksecurity.common.MessageType.UnsupportedMessageTypeException;

public class MessageHandler implements Runnable {
	private Server server;
	private String message;
	private InetAddress serverIp;
	private int serverPort;
	private DatagramSocket outSocket;

	/* Constructor */
	public MessageHandler(Server server, String message, InetAddress ipAddress,
			int port, DatagramSocket outSocket) {
		this.server = server;
		this.message = message;
		this.serverIp = ipAddress;
		this.outSocket = outSocket;
	}

	public void run() {
		// Verify packet header length
		if (message.length() < 2) {
			System.out.println("Invalid message");

		} else {
			MessageType type = null;
			try {
				type = MessageType.getMessageType(message);
			} catch (UnsupportedMessageTypeException e) {
				System.out.println("Invalid message received");
				return;
			}
			
			message = message.substring(2);
			
			switch(type){
			case CLIENT_SERVER_HELLO:
				this.helloResponse(message);
				break;
			case CLIENT_SERVER_AUTH:
				this.authenticatClient(message);
				break;
			case CLIENT_SERVER_VERIFY:
				this.verifyAuthentication(message);
				break;
			case CLIENT_SERVER_LIST:
				this.listLoggedInUsers(message);
				break;
			case CLIENT_SERVER_TALK_REQUEST:
				this.ticketToClientRequested(message);
				break;
			case CLIENT_SERVER_LOGOUT:
				this.logoutClient(message);
				break;
			default:
				break;
				
			}
		}
	}
	
	private void helloResponse(String message){
		
	}
	
	private void authenticatClient(String message){
		
	}
	
	private void verifyAuthentication(String message){
		
	}
	
	private void listLoggedInUsers(String message){
		
	}
	
	private void ticketToClientRequested(String message){
		
	}
	
	private void logoutClient(String message){
		
	}
}
