package networksecurity.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import networksecurity.common.CryptoLibrary;
import networksecurity.common.CryptoLibrary.EncryptionException;
import networksecurity.common.HeaderHandler;
import networksecurity.common.MessageType;

public class CommandHandler implements Runnable {

	private Client client;

	public CommandHandler(Client client) {
		// TODO Auto-generated constructor stub
		this.client = client;
	}

	public void run() {
		this.handleCommands();
	}

	public void handleCommands() {
		String command = "";
		boolean running = true;

		InputStreamReader inputStream = new InputStreamReader(System.in);
		BufferedReader reader = new BufferedReader(inputStream);

		while (running && !Thread.interrupted()) {

			try {
				command = reader.readLine();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			command = command.trim();

			/* Pressed */
			if (command.length() == 0)
				continue;

			/* split command into arguments */
			String[] argsStrings = command.split(" ", 3);
			int length = argsStrings.length;

			if (length == 1) {
				if (argsStrings[0].toUpperCase().equals(
						CommandType.LIST.toString())) {
					this.listOnlineUsers();
				} else if (argsStrings[0].toUpperCase().equals(
						CommandType.LOGOUT.toString())) {
					this.logout();
					System.exit(0);
				} else if (argsStrings[0].toUpperCase().equals(
						CommandType.SEND.toString())) {
					this.usage();
				} else {
					this.usage();
				}
			}

			else if (length == 3) {
				if (argsStrings[0].toUpperCase().equals(
						CommandType.SEND.toString())) {
					this.sendMessage(argsStrings[1], argsStrings[2]);
				}
				else{
					this.usage();
				}
			} else {
				this.usage();
			}
		}
	}

	private void usage() {
		System.out.println("Usage: [list | logout | send username <message>]");
	}

	private void listOnlineUsers() {
		if (!this.client.clientInfo.isLoggedIn()) {
			System.out.print("Client is not logged in onto the server");
			return;
		}

		long currentTime = System.currentTimeMillis();
		this.client.clientInfo.setUserListTimestamp(currentTime);

		String[] message = new String[2];
		message[0] = String.valueOf(this.client.clientInfo.getUserId());

		String[] encryptedMessage = new String[2];
		encryptedMessage[0] = "LIST";
		encryptedMessage[1] = String.valueOf(currentTime);

		try {
			message[1] = CryptoLibrary.aesEncrypt(this.client.clientInfo.getSecretKey(),
					HeaderHandler.pack(encryptedMessage));

			// Send List Command
			sendMessage(HeaderHandler.pack(message),
					MessageType.CLIENT_SERVER_LIST);

		} catch (EncryptionException e) {
			System.out.println("Error encryting list command");
			e.printStackTrace();
		}
	}

	private void sendMessage(String message, MessageType messageType) {
		this.client.clientInfo.sendMessage(message, messageType, this.client
				.clientInfo.getConnectionInfo().getServerIp(), this.client
				.clientInfo.getConnectionInfo().getServerPort());
	}

	private void sendMessage(String peername, String message) {
		if (peername.equals(this.client.clientInfo.getUserName())) {
			System.out.println("Don't send message to yourself");
			return;
		}
		if (this.client.peers.isExist(peername)) {
			this.client.sendMessage(peername, message);
		} else {
			String[] talkRequest = new String[2];
			talkRequest[0] = String.valueOf(this.client.clientInfo.getUserId());

			long currentTime = System.currentTimeMillis();
			this.client.clientInfo.setUserListTimestamp(currentTime);

			String[] encryptedMessage = new String[3];
			encryptedMessage[0] = "TALK";
			encryptedMessage[1] = peername;
			encryptedMessage[2] = String.valueOf(currentTime);

			try {
				talkRequest[1] = CryptoLibrary.aesEncrypt(
						this.client.clientInfo.getSecretKey(),
						HeaderHandler.pack(encryptedMessage));
				sendMessage(HeaderHandler.pack(talkRequest),
						MessageType.CLIENT_SERVER_TALK_REQUEST);
			} catch (EncryptionException e) {
				System.out.println("Error encryting talk command");
				e.printStackTrace();
			}

			this.client.pendingMessages.put(peername, message);
		}
	}
	
	private void logout(){
		String[] message = new String[2];
		message[0] = this.client.clientInfo.getUserId().toString();
		String[] encryptedMessage = new String[2];
		encryptedMessage[0] = "LOGOUT";
		long timestamp = System.currentTimeMillis();
		this.client.clientInfo.setUserListTimestamp(timestamp);
		encryptedMessage[1] = String.valueOf(timestamp);
		try{
			message[1] = CryptoLibrary.aesEncrypt(this.client.clientInfo.getSecretKey(),
					HeaderHandler.pack(encryptedMessage));

			// Send List Command
			sendMessage(HeaderHandler.pack(message),
					MessageType.CLIENT_SERVER_LOGOUT);

		} catch (EncryptionException e) {
			System.out.println("Error encryting list command");
			e.printStackTrace();
		}
	}
}