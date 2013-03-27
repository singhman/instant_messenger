package networksecurity.client;

import java.net.DatagramSocket;
import java.net.InetAddress;

import networksecurity.common.MessageType;
import networksecurity.common.MessageType.UnsupportedMessageTypeException;

public class MessageHandler implements Runnable {
	private String message;
	private DatagramSocket outSocket;
	private ClientInfo client;
	private int destinationPort;
	private InetAddress destinationIp;

	/* Constructor */
	public MessageHandler(ClientInfo client, String message,
			InetAddress destinationIp, int destinationPort,
			DatagramSocket outSocket) {
		this.client = client;
		this.message = message;
		this.destinationIp = destinationIp;
		this.destinationPort = destinationPort;
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
				System.out.println("Invalid message type received via UDP");
				return;
			}
			
			String typeId = message.substring(0,2);
			message = message.substring(2);
			
			switch(type){
			case SERVER_CLIENT_COOKIE:
				this.cookiehandle(message);
				break;
			case SERVER_CLIENT_AUTH:
				this.authenticateToServer(message);
				break;
			case SERVER_CLIENT_LIST:
				this.pickUserForChat(message);
				break;
			case SERVER_CLIENT_TICKET:
				this.ticketToUser(message);
				break;
			case CLIENT_CLIENT_HELLO:
				this.p2pCommunicationBegin(message);
				break;
			case CLIENT_CLIENT_HELLO_RESPONSE:
				this.p2pauthentication(message);
				break;
			case CLIENT_CLIENT_MESSAGE:
				this.communicate(message);
				break;
			case CLIENT_CLIENT_MUTH_AUTH:
				this.authenticationComplete(message);
				break;
			case SERVER_CLIENT_LOGOUT:
				this.logoutClient(message);
				break;
			default:
				try {
					throw new UnsupportedMessageTypeException(typeId);
				} catch (UnsupportedMessageTypeException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				break;
			}
		}
	}
	
	private void cookiehandle(String message){
		
	}
	
	private void authenticateToServer(String message){
		
	}
	
	private void pickUserForChat(String message) {
		
	}
	
	private void ticketToUser(String message){
		
	}
	
	private void p2pCommunicationBegin(String message){
		
	}
	
	private void p2pauthentication(String message){
		
	}
	
	private void communicate(String message){
		
	}
	
	private void authenticationComplete(String message){
		
	}
	
	private void logoutClient(String message){
		
	}
}