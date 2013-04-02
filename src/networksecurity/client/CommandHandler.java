package networksecurity.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import networksecurity.common.CryptoLibrary;
import networksecurity.common.CryptoLibrary.EncryptionException;
import networksecurity.common.HeaderHandler;
import networksecurity.common.MessageType;

public class CommandHandler implements Runnable {

	private ClientInfo client;

	public CommandHandler(ClientInfo client) {
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

		for (enterCommand(); running && !Thread.interrupted(); enterCommand()) {

			try {
				command = reader.readLine();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			command = command.trim();

			/* Pressed */
			if (command.length() == 0)
				continue;

			/* split command into arguments */
			String[] argsStrings = command.split(" ");
			int length = argsStrings.length;

			if (length == 1) {
				if (argsStrings[0].toUpperCase().equals(
						CommandType.LIST.toString())) {
					listOnlineUsers();

				} else if (argsStrings[0].toUpperCase().equals(
						CommandType.LOGOUT.toString())) {

				} else if (argsStrings[0].toUpperCase().equals(
						CommandType.SEND.toString())) {
					System.out
							.print("Please don't waste resources by sending empty message");
				} else {
					this.usage();
				}
			}

			else if (length > 1) {
				if (argsStrings[0].toUpperCase().equals(
						CommandType.SEND.toString())) {

				}
			}
		}
	}

	private void enterCommand() {
		System.out.println(">>");
	}

	private void usage() {
		System.out.println("Usage: [list | logout | send <message>]");
	}

	private void listOnlineUsers() {
		if (!this.client.isLoggedIn()) {
			System.out.print("Client is not logged in onto the server");
			return;
		}

		long currentTime = System.currentTimeMillis();
		this.client.setUserListTimestamp(currentTime);

		String[] message = new String[2];
		message[0] = String.valueOf(this.client.getUserId());

		String[] encryptedMessage = new String[2];
		encryptedMessage[0] = "LIST";
		encryptedMessage[1] = String.valueOf(currentTime);

		try {
			message[1] = CryptoLibrary.aesEncrypt(this.client.getSecretKey(),
					HeaderHandler.pack(encryptedMessage));

			// Send List Command
			sendMessageToServer(HeaderHandler.pack(message),
					MessageType.CLIENT_SERVER_LIST);

		} catch (EncryptionException e1) {
			System.out.println("Error encryting list command");
			e1.printStackTrace();
		}
	}

	private void sendMessageToServer(String message, MessageType messageType) {
		this.client.sendMessage(message, messageType, this.client
				.getConnectionInfo().getServerIp(), this.client
				.getConnectionInfo().getServerPort());
	}

	private void sendMessageToClient(String message, MessageType messageType) {
		this.client.sendMessage(message, messageType, this.client
				.getConnectionInfo().getServerIp(), this.client
				.getConnectionInfo().getServerPort());
	}
}