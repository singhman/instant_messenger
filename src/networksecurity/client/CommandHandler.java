package networksecurity.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;

import networksecurity.common.CryptoLibrary;
import networksecurity.common.CryptoLibrary.EncryptionException;
import networksecurity.common.CryptoLibrary.HmacException;
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

				} else if (argsStrings[0].toUpperCase().equals(
						CommandType.SEND.toString())) {
					System.out.print("Please specify username and message");
					this.usage();
				} else {
					this.usage();
				}
			}

			else if (length > 1) {
				if (argsStrings[0].toUpperCase().equals(
						CommandType.SEND.toString())) {
					// Verify format of send command
					if (argsStrings.length < 3) {
						System.out.println("Invalid send command");
					} else {
						this.sendMessage(argsStrings[1], argsStrings[2]);
					}
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

		} catch (EncryptionException e) {
			System.out.println("Error encryting list command");
			e.printStackTrace();
		}
	}

	private void sendMessageToServer(String message, MessageType messageType) {
		this.client.sendMessage(message, messageType, this.client
				.getConnectionInfo().getServerIp(), this.client
				.getConnectionInfo().getServerPort());
	}

	private void sendMessageToClient(String message, MessageType messageType,
			InetAddress destIp, int destPort) {
		this.client.sendMessage(message, messageType, destIp, destPort);
	}

	private void sendMessage(String peername, String message) {
		if(peername.equals(this.client.getUserName())){
			System.out.println("Don't send message to yourself");
			return;
		}
		if (this.client.isPeerExist(peername)) {
			PeerInfo peerInfo = this.client.getPeerByUserName(peername);

			if (peerInfo == null) {
				System.out.println(peername + "is not online anymore");
				return;
			}
			String[] messageParams = new String[2];
			messageParams[0] = this.client.getUserId().toString();
			
			String[] encryptedMessageParams = new String[]{message, String.valueOf(System.currentTimeMillis())};
			String encryptedMessage = null;
			try {
				encryptedMessage = CryptoLibrary.aesEncrypt(
					peerInfo.getSecretKey(),
					HeaderHandler.pack(encryptedMessageParams)
				);
			} catch (EncryptionException e) {
				System.out.println("Error encrypting message");
				e.printStackTrace();
				return;
			}
			
			String hMac;
			try {
				hMac = CryptoLibrary.hmacCreate(
					peerInfo.getSecretKey(), encryptedMessage
				);
			} catch (HmacException e) {
				System.out.println("Error generating hmac for message");
				e.printStackTrace();
				return;
			}
			
			messageParams[1] = hMac;
			
			sendMessageToClient(HeaderHandler.pack(messageParams), MessageType.CLIENT_CLIENT_MESSAGE, peerInfo.getPeerIp(), peerInfo.getPeerPort());

		} else {
			String[] talkRequest = new String[2];
			talkRequest[0] = String.valueOf(this.client.getUserId());

			long currentTime = System.currentTimeMillis();
			this.client.setUserListTimestamp(currentTime);

			String[] encryptedMessage = new String[3];
			encryptedMessage[0] = "TALK";
			encryptedMessage[1] = peername;
			encryptedMessage[2] = String.valueOf(currentTime);

			try {
				talkRequest[1] = CryptoLibrary.aesEncrypt(
						this.client.getSecretKey(),
						HeaderHandler.pack(encryptedMessage));
				sendMessageToServer(HeaderHandler.pack(talkRequest),
						MessageType.CLIENT_SERVER_TALK_REQUEST);
			} catch (EncryptionException e) {
				System.out.println("Error encryting talk command");
				e.printStackTrace();
			}
		}
	}
}