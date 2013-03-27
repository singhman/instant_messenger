package networksecurity.client;

import java.net.DatagramSocket;
import java.net.InetAddress;

public class MessageHandler implements Runnable{
	private String message;
	private DatagramSocket outSocket;
	private ClientInfo client;
	private int destinationPort;
	private InetAddress destinationIp;
	
	/* Constructor */
	public MessageHandler(ClientInfo client,String message, InetAddress destinationIp, int destinationPort, DatagramSocket outSocket){
		this.client = client;
		this.message = message;
		this.destinationIp = destinationIp;
		this.destinationPort = destinationPort;
		this.outSocket = outSocket;
	}
	
	public void run(){
		
	}
}