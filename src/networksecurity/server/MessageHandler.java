package networksecurity.server;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;

import javax.crypto.SecretKey;

import networksecurity.common.CookieGenerator;
import networksecurity.common.CryptoHelper;
import networksecurity.common.CryptoHelper.DecryptionException;
import networksecurity.common.CryptoHelper.KeyCreationException;
import networksecurity.common.MessageType;
import networksecurity.common.HeaderHandler;
import networksecurity.common.MessageType.UnsupportedMessageTypeException;

public class MessageHandler implements Runnable {
	private Server server;
	private String message;
	private InetAddress clientIp;
	private int clientPort;
	private DatagramSocket outSocket;

	/* Constructor */
	public MessageHandler(Server server, String message, InetAddress ipAddress,
			int port, DatagramSocket outSocket) {
		this.server = server;
		this.message = message;
		this.clientIp = ipAddress;
		this.clientPort = port;
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

			switch (type) {
			case CLIENT_SERVER_HELLO:
				this.helloResponse(message);
				break;
			case CLIENT_SERVER_AUTH:
				this.authenticateClient(message);
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

	private void sendMessage(String message, MessageType messageType) {
		message = messageType.createMessage(message);

		byte[] messageBytes;
		try {
			messageBytes = message.getBytes(CryptoHelper.CHARSET);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return;
		}

		DatagramPacket packet = new DatagramPacket(messageBytes,
				messageBytes.length, this.clientIp, this.clientPort);
		try {
			outSocket.send(packet);
		} catch (IOException e) {
			System.out.println("Error sending packet");
			e.printStackTrace();
			return;
		}
	}

	private void helloResponse(String message) {
		try {
			this.sendMessage(String.valueOf(CookieGenerator
					.generateCookie(this.clientIp)),
					MessageType.SERVER_CLIENT_COOKIE);
		} catch (Exception e) {
			System.out.println("Exception:" + e);
		}
	}

	private void authenticateClient(String message) {
		ArrayList<String> response = HeaderHandler.unpack(message);

		if (CookieGenerator.verifyCookie(this.clientIp, response.get(0))) {
			System.out.println("DEBUG: Cookie matches");
		} else {
			System.out.print("DEBUG: Wrong Coookie");
			return;
		}

		String authRequest = null;
		try {
			System.out.println("Server Encrypted Key Length is " + response.get(1).length());
			SecretKey key;
			
			key = CryptoHelper.aesCreateKey(CryptoHelper.rsaDecrypt(
						server.serverInfo.getServerPrivateKey(), response.get(1))
						.getBytes(CryptoHelper.CHARSET));
			
			authRequest = CryptoHelper.aesDecrypt(key, response.get(2));
		} catch (DecryptionException e) {
			System.out.println("Error decrypting authentication request:");
			e.printStackTrace();
			return;
		} catch (KeyCreationException e) {
			System.out.println("Error creating key from authentication");
			e.printStackTrace();
			return;
		}catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return;
		}
		
		final ArrayList<String> decryptedList = HeaderHandler.unpack(authRequest);
//		final String nonce = decryptedList.get(3);
//		System.out.println(Long.valueOf(nonce).toString());
		
	}

	private void verifyAuthentication(String message) {

	}

	private void listLoggedInUsers(String message) {

	}

	private void ticketToClientRequested(String message) {

	}

	private void logoutClient(String message) {

	}
}
