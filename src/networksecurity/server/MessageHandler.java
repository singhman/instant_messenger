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

import networksecurity.common.CookieManager;
import networksecurity.common.CryptoLibrary;
import networksecurity.common.NonceManager;
import networksecurity.common.TimestampManager;
import networksecurity.common.CryptoLibrary.DecryptionException;
import networksecurity.common.CryptoLibrary.EncryptionException;
import networksecurity.common.CryptoLibrary.KeyCreationException;
import networksecurity.common.MessageType;
import networksecurity.common.HeaderHandler;
import networksecurity.common.MessageType.UnsupportedMessageTypeException;
import networksecurity.common.TicketManager;

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
				this.authenticationComplete(message);
				break;
			case CLIENT_SERVER_LIST:
				this.listLoggedInUsers(message);
				break;
			case CLIENT_SERVER_TALK_REQUEST:
				this.ticketToUser(message);
				break;
			case CLIENT_SERVER_LOGOUT:
				this.logoutUser(message);
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
			this.sendMessage(
					String.valueOf(CookieManager.generateCookie(this.clientIp)),
					MessageType.SERVER_CLIENT_COOKIE);
		} catch (Exception e) {
			System.out.println("Exception:" + e);
		}
	}

	private void authenticateClient(String message) {
		ArrayList<String> response = HeaderHandler.unpack(message);

		if (!CookieManager.verifyCookie(this.clientIp, response.get(0))) {
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
		final String clientNonce = decryptedList.get(3);

		final String username = decryptedList.get(0);

		if (!this.server.isRegistered(username)) {
			System.out.println("User not resgistered");
			return;
		}
		
		if(this.server.isOnline(username)){
			System.out.println("User already online");
			return;
		}

		final User user = this.server.getUser(username);

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

		if (this.server.isAlreadyOnline(clientPort, clientIp)) {
			System.out.println("Client already online: Same port and IP address");
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

		final UUID userId = UUID.randomUUID();
		user.setUserId(userId);
		String encryptedResponse = null;

		try {

			final String[] encryptedResponseParams = new String[3];
			final long serverNonce = NonceManager.generateNonce();
			encryptedResponseParams[0] = userId.toString();
			encryptedResponseParams[1] = clientNonce;
			encryptedResponseParams[2] = String.valueOf(serverNonce);
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
			if(NonceManager.verifyNonce(nonce)){
				System.out.println("Authentication Complete");
			} else{
				System.out.println("Authentication Incomplete: Wrong Nonce");
				return;
			}

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
		final ArrayList<String> listRequest = HeaderHandler.unpack(message);
		User user = this.server.getOnlineUserByUUID(UUID.fromString(listRequest
				.get(0)));

		if (user == null) {
			System.out.println("User doesn't exist in online users");
			return;
		}

		String decryptedMessage;
		try {
			decryptedMessage = CryptoLibrary.aesDecrypt(user.getSessionKey(),
					listRequest.get(1));
		} catch (DecryptionException e) {
			System.out.println("Error decrypting user listing string");
			e.printStackTrace();

			return;
		}

		final ArrayList<String> decryptedParams = HeaderHandler
				.unpack(decryptedMessage);
		final Long timestamp = Long.valueOf(decryptedParams.get(1));

		if (TimestampManager.isExpired(timestamp)) {
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

	private void ticketToUser(String message) {
		final ArrayList<String> talkRequest = HeaderHandler.unpack(message);
		User from = this.server.getOnlineUserByUUID(UUID.fromString(talkRequest
				.get(0)));

		if (from == null) {
			System.out.println("User doesn't exist in online users");
			return;
		}

		String decryptedMessage;
		try {
			decryptedMessage = CryptoLibrary.aesDecrypt(from.getSessionKey(),
					talkRequest.get(1));
		} catch (DecryptionException e) {
			System.out.println("Error decrypting user talk request");
			e.printStackTrace();
			return;
		}

		final ArrayList<String> decryptedParams = HeaderHandler
				.unpack(decryptedMessage);
		final Long timestamp = Long.valueOf(decryptedParams.get(2));

		if (TimestampManager.isExpired(timestamp)) {
			System.out.println("Expired talk request timestamp");
			return;
		}

		User to = null;
		
		try {
			String toUserName = decryptedParams.get(1);
			if(!this.server.isRegistered(toUserName)){
				System.out.println(toUserName + " is not registered");
				return;
			}
			
			to = this.server.getOnlineUser(decryptedParams.get(1));
			if (to == null) {
				System.out.println(decryptedParams.get(1) + " is not online");
				return;
			}

			SecretKey key = null;
			try {
				key = CryptoLibrary.aesGenerateKey();
			} catch (KeyCreationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			String[] talkResponse = new String[7];
			talkResponse[0] = to.getUsername();
			talkResponse[1] = to.getUserIp().getHostAddress();
			talkResponse[2] = String.valueOf(to.getUserPort());
			talkResponse[3] = new String(key.getEncoded(),
					CryptoLibrary.CHARSET);
			talkResponse[4] = CryptoLibrary.aesEncrypt(to.getSessionKey(), HeaderHandler.pack(TicketManager.getTicket(from, to.getUsername(), key)));
			talkResponse[5] = String.valueOf(timestamp + 1);
			talkResponse[6] = to.getUserId().toString();
			String messageToSend = CryptoLibrary.aesEncrypt(from.getSessionKey(), HeaderHandler.pack(talkResponse));
			sendMessage(messageToSend, MessageType.SERVER_CLIENT_TICKET);

		} catch (Exception e) {
			System.out.println("Exception:" + e.toString());
			e.printStackTrace();
			return;
		}
	}

	private void logoutUser(String message) {
		final ArrayList<String> ResponseReceived = HeaderHandler.unpack(message);
		UUID userId = UUID.fromString(ResponseReceived.get(0));
		User user = this.server.getOnlineUserByUUID(userId);
		if(user == null){
			System.out.println("User is not online");
			return;
		}
		
		String decryptedMessage = null;
		try {
			decryptedMessage = CryptoLibrary.aesDecrypt(user.getSessionKey(), ResponseReceived.get(1));
		} catch (DecryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		final ArrayList<String> logoutParams = HeaderHandler.unpack(decryptedMessage);
		final Long timestamp = Long.valueOf(logoutParams.get(1));

		if (TimestampManager.isExpired(timestamp)) {
			System.out.println("Expired logout timestamp");
			return;
		} 
		
		String logoutResponse = String.valueOf(timestamp + 1);
		String encryptedResponse = null;
		try {
			encryptedResponse = CryptoLibrary.aesEncrypt(user.getSessionKey(), logoutResponse);
		} catch (EncryptionException e) {
			// TODO: handle exception
			e.printStackTrace();
			return;
		}
		
		sendMessage(encryptedResponse, MessageType.SERVER_CLIENT_LOGOUT);
		
		this.server.destroySessionKey(userId);
		this.server.logoutUser(userId);
	}
}
