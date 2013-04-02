package networksecurity.server;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.UUID;

import javax.crypto.SecretKey;

import networksecurity.common.CookieGenerator;
import networksecurity.common.CryptoLibrary;
import networksecurity.common.CryptoLibrary.DecryptionException;
import networksecurity.common.CryptoLibrary.EncryptionException;
import networksecurity.common.CryptoLibrary.KeyCreationException;
import networksecurity.common.MessageType;
import networksecurity.common.HeaderHandler;
import networksecurity.common.MessageType.UnsupportedMessageTypeException;

public class MessageHandler implements Runnable {

	private static final int TIMESTAMP_LIMIT = 1 * 60 * 1000;
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
				this.authenticationComplete(message);
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
			messageBytes = message.getBytes(CryptoLibrary.CHARSET);
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
			SecretKey key;

			key = CryptoLibrary.aesCreateKey(CryptoLibrary.rsaDecrypt(
					server.serverInfo.getServerPrivateKey(), response.get(1))
					.getBytes(CryptoLibrary.CHARSET));

			authRequest = CryptoLibrary.aesDecrypt(key, response.get(2));

		} catch (DecryptionException e) {
			System.out.println("Error decrypting authentication request:");
			e.printStackTrace();
			return;
		} catch (KeyCreationException e) {
			System.out.println("Error creating key from authentication");
			e.printStackTrace();
			return;
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return;
		}

		final ArrayList<String> decryptedList = HeaderHandler
				.unpack(authRequest);
		final String nonce1 = decryptedList.get(3);
		System.out.println("Nonce:" + Long.valueOf(nonce1).toString());

		final String username = decryptedList.get(0);

		if (!server.isRegistered(username)) {
			System.out.println("User not resgistered");
			return;
		}

		final User user = server.getUser(username);

		if (user == null) {
			System.out.println("Unknown username: " + decryptedList.get(0));
			return;
		}

		String validationHash = CryptoLibrary
				.generateValidationHash(decryptedList.get(1));
		if (!validationHash.equals(user.getPasswordHash())) {
			System.out
					.print("Password doesn't match for " + user.getUsername());
			return;
		}

		if (this.server.isAlreadyOnlineByPort(clientPort)) {
			System.out.println("User already online: Port is same");
		}

		PublicKey publicKey = null;
		SecretKey secretKey = null;

		try {
			final KeyPair keyPair = CryptoLibrary.dhGenerateKeyPair();
			final PrivateKey privateKey = keyPair.getPrivate();
			publicKey = keyPair.getPublic();
			secretKey = CryptoLibrary.dhGenerateSecretKey(privateKey,
					decryptedList.get(2).getBytes(CryptoLibrary.CHARSET));
		} catch (KeyCreationException e) {
			System.out.println("Error generating diffie hellman key");
			e.printStackTrace();
			return;
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return;
		}

		/* Note: Need to check if user already exist */

		final UUID userId = UUID.randomUUID();
		user.setUserId(userId);
		String encryptedResponse = null;

		try {

			final String[] encryptedResponseParams = new String[3];
			final long nonce2 = 1;
			encryptedResponseParams[0] = userId.toString();
			encryptedResponseParams[1] = nonce1;
			encryptedResponseParams[2] = String.valueOf(nonce2);
			encryptedResponse = CryptoLibrary.aesEncrypt(secretKey,
					HeaderHandler.pack(encryptedResponseParams));

		} catch (EncryptionException e) {
			System.out.println("Error performing encryption");
			e.printStackTrace();
			return;
		}

		user.setUserIp(this.clientIp);
		user.setUserPort(this.clientPort);
		user.setUserSessionKey(secretKey);

		final String responseParams[] = new String[3];
		try {
			String dhpublicKey = new String(publicKey.getEncoded(),
					CryptoLibrary.CHARSET);
			responseParams[0] = dhpublicKey;

			/*
			 * signing the decoded gs mod p string so at the time of
			 * verification, need to verify with the decoded string.
			 */
			responseParams[1] = new String(CryptoLibrary.sign(
					server.serverInfo.getServerPrivateKey(), dhpublicKey),
					CryptoLibrary.CHARSET);
			responseParams[2] = encryptedResponse;
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
		}
		final String messageResponse = HeaderHandler.pack(responseParams);

		sendMessage(messageResponse, MessageType.SERVER_CLIENT_AUTH);
	}

	private void authenticationComplete(String message) {
		final ArrayList<String> responseReceived = HeaderHandler
				.unpack(message);
		UUID userId = UUID.fromString(responseReceived.get(0));
		User user = this.server.getRegisteredUserByUUID(userId);
		if (user == null) {
			System.out.println("User doesn't exist with UserId " + userId);
		}
		try {
			long nonce = Long.valueOf(CryptoLibrary.aesDecrypt(
					user.getSessionKey(), responseReceived.get(1)));
			/* Note: Comapare nonces */
			System.out.println("Authentication Complete");

		} catch (NumberFormatException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (DecryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		this.server.loginUser(userId, user);
	}

	private void listLoggedInUsers(String message) {
		final ArrayList<String> params = HeaderHandler.unpack(message);
		User user = this.server.getOnlineUserByUUID(UUID.fromString(params
				.get(0)));

		String decryptedMessage;
		try {
			decryptedMessage = CryptoLibrary.aesDecrypt(user.getSessionKey(),
					params.get(1));
		} catch (DecryptionException e) {
			System.out.println("Error decrypting user listing string");
			e.printStackTrace();

			return;
		}

		final ArrayList<String> decryptedParams = HeaderHandler
				.unpack(decryptedMessage);
		final Long timestamp = Long.valueOf(decryptedParams.get(1));
		final Long currentTime = System.currentTimeMillis();

		if (Math.abs(timestamp - currentTime) >= TIMESTAMP_LIMIT) {
			System.out.println("Expired timestamp");
			return;
		}

		final String[] returnParams = new String[2];
		returnParams[0] = server.getUserList();
		returnParams[1] = String.valueOf(timestamp + 1);

		String encryptedReturn;

		try {
			encryptedReturn = CryptoLibrary.aesEncrypt(user.getSessionKey(),
					HeaderHandler.pack(returnParams));
			sendMessage(encryptedReturn, MessageType.SERVER_CLIENT_LIST);
		} catch (EncryptionException e) {
			System.out.println("Error encrypting user list");
			e.printStackTrace();
			return;
		}
	}

	private void ticketToClientRequested(String message) {

	}

	private void logoutClient(String message) {

	}
}
