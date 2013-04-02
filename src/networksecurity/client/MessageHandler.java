package networksecurity.client;

import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.UUID;

import javax.crypto.SecretKey;

import networksecurity.common.CryptoLibrary;
import networksecurity.common.CryptoLibrary.EncryptionException;
import networksecurity.common.CryptoLibrary.KeyCreationException;
import networksecurity.common.MessageType;
import networksecurity.common.CryptoLibrary.DecryptionException;
import networksecurity.common.MessageType.UnsupportedMessageTypeException;
import networksecurity.common.HeaderHandler;

public class MessageHandler implements Runnable {
	private String message;
	private ClientInfo client;
	private int destinationPort;
	private InetAddress destinationIp;

	/* Constructor */
	public MessageHandler(ClientInfo client, String message,
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
		this.client.sendMessage(message, messageType, this.destinationIp,
				this.destinationPort);
	}

	private void authenticationBegin(String message) {
		String[] messageStrings = new String[4];

		/* Need a nonce generator and verifier */
		final long nonce = 0;

		try {
			this.client.setdhKeyPair(CryptoLibrary.dhGenerateKeyPair());

			messageStrings[0] = this.client.getUserName();
			messageStrings[1] = this.client.getPassword();
			messageStrings[2] = new String(this.client.getDHKeyPair()
					.getPublic().getEncoded(), CryptoLibrary.CHARSET);
			messageStrings[3] = String.valueOf(nonce);

			SecretKey key = CryptoLibrary.aesGenerateKey();

			/*
			 * Problem: Data must not be longer than 117 bytes to encrypt with
			 * RSA
			 */
			String encryptedMessage = CryptoLibrary.aesEncrypt(key,
					HeaderHandler.pack(messageStrings));

			String encryptedKey = CryptoLibrary.rsaEncrypt(
					this.client.getServerPublicKey(),
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

		System.out.println("DEBUG: Message Received length is"
				+ message.length());
		ArrayList<String> response = HeaderHandler.unpack(message);

		try {
			byte[] publicExp = response.get(0).getBytes(CryptoLibrary.CHARSET);
			this.client.setSecretKey(CryptoLibrary.dhGenerateSecretKey(
					this.client.getDHKeyPair().getPrivate(), publicExp));
			byte[] signedResponse = response.get(1).getBytes(
					CryptoLibrary.CHARSET);

			/*
			 * Need to verify the decoded string received, not with the encoded
			 * bytes
			 */
			if (CryptoLibrary.verify(this.client.getServerPublicKey(),
					response.get(0), signedResponse)) {
				System.out.print("Signature Verified");
			} else {
				System.out.println("Signature not verified");
				return;
			}

			final ArrayList<String> decodedParams = HeaderHandler
					.unpack(CryptoLibrary.aesDecrypt(this.client.getSecretKey(),
							response.get(2)));

			this.client.setUserId(UUID.fromString(decodedParams.get(0)));

			/* Note: need to verify nonce decodedParams.get(1) */
			long nonce2 = Long.valueOf(decodedParams.get(2));

			String[] responseToServer = new String[2];
			responseToServer[0] = this.client.getUserId().toString();
			responseToServer[1] = CryptoLibrary.aesEncrypt(this.client.getSecretKey(),String.valueOf(nonce2));
			
			sendMessage(HeaderHandler.pack(responseToServer), MessageType.CLIENT_SERVER_VERIFY);
			this.client.setIsLoggedIn(true);
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
			message = CryptoLibrary.aesDecrypt(this.client.getSecretKey(), message);
			final ArrayList<String> params = HeaderHandler.unpack(message);
			
			if (Long.valueOf(params.get(1)).equals(this.client.getUserListTimestamp() + 1)) {
				this.client.setUserListTimestamp(0);
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
		
		try{
			message = CryptoLibrary.aesDecrypt(this.client.getSecretKey(), message);
			final ArrayList<String> talkResponse = HeaderHandler.unpack(message);
			
			String peer = talkResponse.get(0);
			InetAddress peerIp = InetAddress.getByName(talkResponse.get(1));
			int peerPort = Integer.valueOf(talkResponse.get(2));
			SecretKey tempSessionKey = null;
			try {
				tempSessionKey = CryptoLibrary.aesCreateKey(talkResponse.get(3).getBytes(CryptoLibrary.CHARSET));
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (KeyCreationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			peerInfo = new PeerInfo(peer, peerIp, peerPort, tempSessionKey);
			this.client.peers.put(peerInfo.getPeerUsername(), peerInfo);
			
			ticketToPeer = talkResponse.get(4);
			
			if (Long.valueOf(talkResponse.get(5)).equals(this.client.getUserListTimestamp() + 1)) {
				this.client.setUserListTimestamp(0);
			}
			else{
				System.out.println("Ticket Response received from server is not authentic");
				return;
			}
			
		} catch(DecryptionException e){
			e.printStackTrace();
			return;
		}catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		try {
			this.client.setdhKeyPair(CryptoLibrary.dhGenerateKeyPair());
		} catch (KeyCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		String[] responseToPeer = new String[2];
		responseToPeer[0] = ticketToPeer;
		String[] helloMessage = new String[5];
		try{
			helloMessage[0] = "HELLO";
			helloMessage[1] = this.client.getUserName();
			helloMessage[2] = peerInfo.getPeerUsername();
			helloMessage[3] = new String(this.client.getDHKeyPair()
					.getPublic().getEncoded(), CryptoLibrary.CHARSET);
			helloMessage[4] = "0";
		} catch(UnsupportedEncodingException e){
			e.printStackTrace();
			return;
		}
		
		try {
			responseToPeer[1] = CryptoLibrary.aesEncrypt(peerInfo.getTempSessionKey(), HeaderHandler.pack(helloMessage));
		} catch (EncryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		sendMessage(HeaderHandler.pack(responseToPeer), MessageType.CLIENT_CLIENT_HELLO);
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