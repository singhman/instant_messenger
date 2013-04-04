package networksecurity.client;

import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.UUID;

import javax.crypto.SecretKey;

import networksecurity.common.CryptoLibrary;
import networksecurity.common.CryptoLibrary.HmacException;
import networksecurity.common.NonceManager;
import networksecurity.common.CryptoLibrary.EncryptionException;
import networksecurity.common.CryptoLibrary.KeyCreationException;
import networksecurity.common.MessageType;
import networksecurity.common.CryptoLibrary.DecryptionException;
import networksecurity.common.MessageType.UnsupportedMessageTypeException;
import networksecurity.common.HeaderHandler;

public class MessageHandler implements Runnable {

	private final static long TICKET_EXPIRATION = 5 * 60 * 1000;
	private final static long MESSAGE_EXPIRATION = 1 * 60 * 1000;

	private String message;
	private Client client;
	private int destinationPort;
	private InetAddress destinationIp;

	/* Constructor */
	public MessageHandler(Client client, String message,
			InetAddress destinationIp, int destinationPort) {
		this.client = client;
		this.message = message;
		this.destinationIp = destinationIp;
		this.destinationPort = destinationPort;
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
				this.displayUsersList(message);
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
			case CLIENT_CLIENT_MUTH_AUTH:
				this.authenticationCompleteWithClient(message);
				break;
			case CLIENT_CLIENT_MESSAGE:
				this.communicate(message);
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
		this.client.clientInfo.sendMessage(message, messageType, this.destinationIp,
				this.destinationPort);
	}

	private void sendMessage(String message, MessageType messageType,
			InetAddress destIp, int destPort) {
		this.client.clientInfo.sendMessage(message, messageType, destIp, destPort);
	}

	private void authenticationBegin(String message) {
		String[] authRequest = new String[4];

		final long nonce = NonceManager.generateNonce();

		try {
			this.client.clientInfo.setdhKeyPair(CryptoLibrary.dhGenerateKeyPair());

			authRequest[0] = this.client.clientInfo.getUserName();
			authRequest[1] = this.client.clientInfo.getPassword();
			authRequest[2] = new String(this.client.clientInfo.getDHKeyPair().getPublic()
					.getEncoded(), CryptoLibrary.CHARSET);
			authRequest[3] = String.valueOf(nonce);

			SecretKey key = CryptoLibrary.aesGenerateKey();

			/*
			 * Note: Data must not be longer than 117 bytes to encrypt with RSA
			 */
			String encryptedMessage = CryptoLibrary.aesEncrypt(key,
					HeaderHandler.pack(authRequest));

			String encryptedKey = CryptoLibrary.rsaEncrypt(
					this.client.clientInfo.getServerPublicKey(),
					new String(key.getEncoded(), CryptoLibrary.CHARSET));

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
		ArrayList<String> response = HeaderHandler.unpack(message);

		try {
			byte[] publicExp = response.get(0).getBytes(CryptoLibrary.CHARSET);
			this.client.clientInfo.setSecretKey(CryptoLibrary.dhGenerateSecretKey(
					this.client.clientInfo.getDHKeyPair().getPrivate(), publicExp));
			byte[] signedResponse = response.get(1).getBytes(
					CryptoLibrary.CHARSET);

			/*
			 * Verify decoded string received, not with the encoded bytes
			 */
			if (CryptoLibrary.verify(this.client.clientInfo.getServerPublicKey(),
					response.get(0), signedResponse)) {
			} else {
				System.out.println("Signature not verified");
				return;
			}

			final ArrayList<String> decodedParams = HeaderHandler
					.unpack(CryptoLibrary.aesDecrypt(
							this.client.clientInfo.getSecretKey(), response.get(2)));

			this.client.clientInfo.setUserId(UUID.fromString(decodedParams.get(0)));

			if (!NonceManager.verifyNonce(Long.valueOf(decodedParams.get(1)))) {
				System.out
						.println("Wrong Nonce in Client Server Authentication");
			}

			long serverNonce = Long.valueOf(decodedParams.get(2));

			String[] responseToServer = new String[2];
			responseToServer[0] = this.client.clientInfo.getUserId().toString();
			responseToServer[1] = CryptoLibrary.aesEncrypt(
					this.client.clientInfo.getSecretKey(), String.valueOf(serverNonce));

			sendMessage(HeaderHandler.pack(responseToServer),
					MessageType.CLIENT_SERVER_VERIFY);
			this.client.clientInfo.setIsLoggedIn(true);
			/*
			 * Start a thread for handling the commands list , logout, send
			 * <message>
			 */
			(new Thread(new CommandHandler(this.client))).start();

		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
		}
	}

	private void displayUsersList(String message) {
		try {
			message = CryptoLibrary.aesDecrypt(this.client.clientInfo.getSecretKey(),
					message);
			final ArrayList<String> params = HeaderHandler.unpack(message);

			if (Long.valueOf(params.get(1)).equals(
					this.client.clientInfo.getUserListTimestamp() + 1)) {
				this.client.clientInfo.setUserListTimestamp(0);
				System.out.println(params.get(0));
			}
		} catch (DecryptionException e) {
			e.printStackTrace();
			return;
		}
	}

	private void ticketToUser(String message) {
		PeerInfo peerInfo = null;
		String ticketToPeer = null;

		try {
			message = CryptoLibrary.aesDecrypt(this.client.clientInfo.getSecretKey(),
					message);
			final ArrayList<String> talkResponse = HeaderHandler
					.unpack(message);

			String peer = talkResponse.get(0);
			InetAddress peerIp = InetAddress.getByName(talkResponse.get(1));
			int peerPort = Integer.valueOf(talkResponse.get(2));
			SecretKey tempSessionKey = null;
			try {
				tempSessionKey = CryptoLibrary.aesCreateKey(talkResponse.get(3)
						.getBytes(CryptoLibrary.CHARSET));
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (KeyCreationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			UUID peerUserId = UUID.fromString(talkResponse.get(6));

			peerInfo = new PeerInfo(peer, peerIp, peerPort, peerUserId,
					tempSessionKey);
			if (!this.client.peers.isExist(peerUserId)) {
				this.client.peers.addPeer(peerUserId, peerInfo);
			}

			ticketToPeer = talkResponse.get(4);

			if (Long.valueOf(talkResponse.get(5)).equals(
					this.client.clientInfo.getUserListTimestamp() + 1)) {
				this.client.clientInfo.setUserListTimestamp(0);
			} else {
				System.out
						.println("Ticket Response received from server with expired timestamp");
				return;
			}

		} catch (DecryptionException e) {
			e.printStackTrace();
			return;
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		try {
			this.client.clientInfo.setdhKeyPair(CryptoLibrary.dhGenerateKeyPair());
		} catch (KeyCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		String[] responseToPeer = new String[2];
		responseToPeer[0] = ticketToPeer;
		String[] helloMessage = new String[5];
		try {
			helloMessage[0] = "HELLO";
			helloMessage[1] = this.client.clientInfo.getUserName();
			helloMessage[2] = peerInfo.getPeerUsername();
			helloMessage[3] = new String(this.client.clientInfo.getDHKeyPair().getPublic()
					.getEncoded(), CryptoLibrary.CHARSET);
			helloMessage[4] = String.valueOf(NonceManager.generateNonce());
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			return;
		}

		try {
			responseToPeer[1] = CryptoLibrary.aesEncrypt(
					peerInfo.getTempSessionKey(),
					HeaderHandler.pack(helloMessage));
		} catch (EncryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		sendMessage(HeaderHandler.pack(responseToPeer),
				MessageType.CLIENT_CLIENT_HELLO, peerInfo.getPeerIp(),
				peerInfo.getPeerPort());
	}

	private void p2pCommunicationBegin(String message) {
		final ArrayList<String> response = HeaderHandler.unpack(message);
		String ticket = null;
		String helloMessage = null;
		SecretKey tempSessionKey = null;
		String peerName = null;
		UUID peerUserId = null;
		PublicKey publicKey = null;
		SecretKey secretKey = null;
		long peerNonce = 0;
		try {
			ticket = CryptoLibrary.aesDecrypt(this.client.clientInfo.getSecretKey(),
					response.get(0));
			final ArrayList<String> ticketParams = HeaderHandler.unpack(ticket);

			if (!this.client.clientInfo.getUserName().equals(ticketParams.get(0))) {
				System.out
						.println("Username Unmatched: This ticket was intended for somebody else");
				return;
			}

			peerName = ticketParams.get(1);
			peerUserId = UUID.fromString(ticketParams.get(2));

			try {
				tempSessionKey = CryptoLibrary.aesCreateKey(ticketParams.get(3)
						.getBytes(CryptoLibrary.CHARSET));
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (KeyCreationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			long timestamp = Long.valueOf(ticketParams.get(4));
			final Long currentTime = System.currentTimeMillis();

			if (Math.abs(timestamp - currentTime) >= TICKET_EXPIRATION) {
				System.out.println("Expired ticket");
				return;
			}

		} catch (DecryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		try {
			helloMessage = CryptoLibrary.aesDecrypt(tempSessionKey,
					response.get(1));
			final ArrayList<String> helloParams = HeaderHandler
					.unpack(helloMessage);

			if (!peerName.equals(helloParams.get(1))) {
				System.out
						.println("Usernames doesn't match in ticket and hello message");
				return;
			}

			if (!this.client.clientInfo.getUserName().equals(helloParams.get(2))) {
				System.out
						.println("This message was intented for somebody else");
				return;
			}

			try {
				final KeyPair keyPair = CryptoLibrary.dhGenerateKeyPair();
				final PrivateKey privateKey = keyPair.getPrivate();
				publicKey = keyPair.getPublic();
				secretKey = CryptoLibrary.dhGenerateSecretKey(privateKey,
						helloParams.get(3).getBytes(CryptoLibrary.CHARSET));
			} catch (KeyCreationException e) {
				System.out.println("Error generating diffie hellman key");
				e.printStackTrace();
				return;
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
				return;
			}
			peerNonce = Long.valueOf(helloParams.get(4));

		} catch (DecryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		PeerInfo peerInfo = new PeerInfo(peerName, this.destinationIp,
				this.destinationPort, peerUserId, tempSessionKey);
		if (peerInfo != null && peerName != null) {
			this.client.peers.addPeer(peerUserId, peerInfo);
		}

		peerInfo.setSecretKey(secretKey);

		String[] helloResponse = new String[3];
		helloResponse[0] = this.client.clientInfo.getUserId().toString();
		try {
			String dhpublicKey = new String(publicKey.getEncoded(),
					CryptoLibrary.CHARSET);
			String dhEncryptedParam = CryptoLibrary.aesEncrypt(tempSessionKey,
					dhpublicKey);
			helloResponse[1] = dhEncryptedParam;
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (EncryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		String[] nonces = new String[2];
		nonces[0] = String.valueOf(peerNonce);
		nonces[1] = String.valueOf(NonceManager.generateNonce());

		try {
			String encryptedNonces = CryptoLibrary.aesEncrypt(
					peerInfo.getSecretKey(), HeaderHandler.pack(nonces));
			helloResponse[2] = encryptedNonces;
		} catch (EncryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		sendMessage(HeaderHandler.pack(helloResponse),
				MessageType.CLIENT_CLIENT_HELLO_RESPONSE);
	}

	private void p2pauthentication(String message) {
		final ArrayList<String> responseReceived = HeaderHandler
				.unpack(message);
		UUID userId = UUID.fromString(responseReceived.get(0));
		PeerInfo peerInfo = this.client.peers.getPeer(userId);
		long peerNonce = 0;

		try {
			String dhPublicKey = CryptoLibrary.aesDecrypt(
					peerInfo.getTempSessionKey(), responseReceived.get(1));
			byte[] publicExp = dhPublicKey.getBytes(CryptoLibrary.CHARSET);
			peerInfo.setSecretKey(CryptoLibrary.dhGenerateSecretKey(this.client
					.clientInfo.getDHKeyPair().getPrivate(), publicExp));

			final ArrayList<String> nonces = HeaderHandler.unpack(CryptoLibrary
					.aesDecrypt(peerInfo.getSecretKey(),
							responseReceived.get(2)));
			if (!NonceManager.verifyNonce(Long.valueOf(nonces.get(0)))) {
				System.out
						.println("Nonces Unmatched in Client client authentication");
				return;
			}
			peerNonce = Long.valueOf(nonces.get(1));
		} catch (KeyCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (DecryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		String[] response = new String[2];
		response[0] = this.client.clientInfo.getUserId().toString();
		try {
			response[1] = CryptoLibrary.aesEncrypt(peerInfo.getSecretKey(),
					String.valueOf(peerNonce));
		} catch (EncryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		sendMessage(HeaderHandler.pack(response),
				MessageType.CLIENT_CLIENT_MUTH_AUTH);
		this.client.sendMessage(peerInfo.getPeerUsername(), this.client.pendingMessages.get(peerInfo.getPeerUsername()));
	}

	private void authenticationCompleteWithClient(String message) {
		final ArrayList<String> responseReceived = HeaderHandler
				.unpack(message);
		PeerInfo peerInfo = this.client.peers.getPeer(UUID
				.fromString(responseReceived.get(0)));

		try {
			String decryptedNonce = CryptoLibrary.aesDecrypt(
					peerInfo.getSecretKey(), responseReceived.get(1));
			if (NonceManager.verifyNonce(Long.valueOf(decryptedNonce))) {
				System.out.println("Authentication Complete");
			}
		} catch (DecryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void communicate(String message) {

		final ArrayList<String> responseParams = HeaderHandler.unpack(message);
		PeerInfo peerInfo = this.client.peers.getPeer(UUID.fromString(responseParams
				.get(0)));
		String content;

		try {
			content = CryptoLibrary.hmacVerify(peerInfo.getSecretKey(),
					responseParams.get(1));
		} catch (HmacException e) {
			e.printStackTrace();
			return;
		}

		try {
			content = CryptoLibrary.aesDecrypt(peerInfo.getSecretKey(),
					content);
		} catch (DecryptionException e) {
			return;
		}
		
		final ArrayList<String> decryptedMessage = HeaderHandler.unpack(content);
		
		long timestamp = Long.valueOf(decryptedMessage.get(1));
		long currentTime = System.currentTimeMillis();
		
		if(Math.abs(timestamp - currentTime) >= MESSAGE_EXPIRATION){
			System.out.println("Message Expired");
			return;
		}
		
		System.out.println(peerInfo.getPeerUsername() + ": " +decryptedMessage.get(0));
	}

	private void logoutClient(String message) {
		String logoutMessage = null;
		try {
			logoutMessage = CryptoLibrary.aesDecrypt(this.client.clientInfo.getSecretKey(), message);
		} catch (DecryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
		}
		
		if (Long.valueOf(logoutMessage).equals(
				this.client.clientInfo.getUserListTimestamp() + 1)) {
			this.client.clientInfo.setUserListTimestamp(0);
		} else {
			System.out
					.println("Logout timestamp expired");
			return;
		}
	}
}