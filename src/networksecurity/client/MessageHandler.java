package networksecurity.client;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

import javax.crypto.SecretKey;

import networksecurity.common.CryptoHelper;
import networksecurity.common.MessageType;
import networksecurity.common.MessageType.UnsupportedMessageTypeException;
import networksecurity.common.HeaderHandler;

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

			String typeId = message.substring(0, 2);
			message = message.substring(2);

			switch (type) {
			case SERVER_CLIENT_COOKIE:
				this.authenticationBegin(message);
				break;
			case SERVER_CLIENT_AUTH:
				this.authenticationCompleteWithServer(message);
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
				this.authenticationCompleteWithClient(message);
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

	private void sendMessage(String message, MessageType messageType) {
		sendMessage(message, messageType, this.destinationIp,
				this.destinationPort);
	}

	/* Send a message to given ip and port */
	private void sendMessage(String message, MessageType messageType,
			InetAddress destIp, int destPort) {
		message = messageType.createMessage(message);
		byte[] messageBytes;

		try {
			messageBytes = message.getBytes(CryptoHelper.CHARSET);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return;
		}

		DatagramPacket packet = new DatagramPacket(messageBytes,
				messageBytes.length, destIp, destPort);

		try {
			outSocket.send(packet);
		} catch (IOException e) {
			System.out.println("Error sending packet");
			e.printStackTrace();
			return;
		}
	}

	private void authenticationBegin(String message) {
		String[] messageStrings = new String[4];

		/* Need a nonce generator and verifier */
		final long nonce = 0;

		try {
			this.client.setdhKeyPair(CryptoHelper.dhGenerateKeyPair());

			messageStrings[0] = this.client.getUserName();
			messageStrings[1] = this.client.getPassword();
			messageStrings[2] = new String(this.client.getdhKeyPair()
					.getPublic().getEncoded(), CryptoHelper.CHARSET);
			messageStrings[3] = String.valueOf(nonce);

			SecretKey key = CryptoHelper.aesGenerateKey();

			/*
			 * Problem: Data must not be longer than 117 bytes to encrypt with
			 * RSA
			 */
			String encryptedMessage = CryptoHelper.aesEncrypt(key,
					HeaderHandler.pack(messageStrings));
			
			String encryptedKey = CryptoHelper.rsaEncrypt(this.client.getServerPublicKey(),
					new String(key.getEncoded(),CryptoHelper.CHARSET));

			String[] response = new String[3];
			response[0] = message;
			response[1] = encryptedKey;
			response[2] = encryptedMessage;
			sendMessage(HeaderHandler.pack(response),
					MessageType.CLIENT_SERVER_AUTH);
		} catch (Exception e) {
			System.out.println("Unable to send authentication packet");
			e.printStackTrace();
		}
	}

	private void authenticationCompleteWithServer(String message) {

	}

	private void pickUserForChat(String message) {

	}

	private void ticketToUser(String message) {

	}

	private void p2pCommunicationBegin(String message) {

	}

	private void p2pauthentication(String message) {

	}

	private void communicate(String message) {

	}

	private void authenticationCompleteWithClient(String message) {

	}

	private void logoutClient(String message) {

	}
}