package networksecurity.client;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * A class that takes care of listening for incoming TCP socket connections.
 */
public class ClientListener implements Runnable {
	private final Client client;
	private final int port;
	
	/**
	 * @param client The client.
	 * 
	 * @param port The port this client listens for TCP connections on.
	 */
	public ClientListener(Client client, int port) {
		this.client = client;
		this.port = port;
	}
	
	/* (non-Javadoc)
	 * @see java.lang.Runnable#run()
	 */
	@Override
	public void run() {
		// Listen for connection
		ServerSocket serverSocket;
		Socket clientSocket;
		
		try {
		    serverSocket = new ServerSocket(this.port);
			while ((clientSocket = serverSocket.accept()) != null) {
				
				new SocketReceiver(clientSocket);
			}
		} catch (IOException e) {
		    System.out.println("Could not listen on port");
		    System.exit(-1);
		}
		
	}
	
	/**
	 * Class that handles a received socket connection.
	 */
	private class SocketReceiver implements Runnable {

		private final Socket clientSocket;
		
		/**
		 * @param clientSocket The TCP socket to handle.
		 */
		public SocketReceiver(Socket clientSocket) {
			this.clientSocket = clientSocket;
			(new Thread(this)).start();
		}
		
		/* (non-Javadoc)
		 * @see java.lang.Runnable#run()
		 */
		@Override
		public void run() {
			
		}
	}
}
