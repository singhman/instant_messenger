package client;

import java.net.DatagramPacket;
import java.util.HashMap;

import common.CryptoLibrary;
import common.HeaderHandler;
import common.MessageType;
import common.ConfigReader.ConfigReaderException;
import common.CryptoLibrary.EncryptionException;
import common.CryptoLibrary.HmacException;


public class Client {

	public ClientInfo clientInfo = null;
	public Peers peers = new Peers();
	public HashMap<String, String> pendingMessages = new HashMap<String, String>();
	public boolean running = true;

	/* starting point of the client */
	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		
		Client client = new Client();
		String configFile = "src/resources/client.cfg";
		if (args.length == 1) {
			configFile = args[0];
		}
		client.loadClientInfofromConfigFile(configFile);
	}
	
	public void loadClientInfofromConfigFile(String configFile){
		ClientConfigReader configReader;
		try {
			configReader = new ClientConfigReader(configFile);
		} catch (ConfigReaderException e) {
			System.out.println("Unable to read config file");
			e.printStackTrace();
			return;
		}

		this.clientInfo = new ClientInfo(configReader);
		try {
			this.clientInfo.loginPrompt();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		recieveMessage();
	}

	public void recieveMessage(){
		byte[] buf = new byte[1024];
		
		/* Start listening */
		try{
			
			DatagramPacket packet = new DatagramPacket(buf, buf.length);
			
			while(running){
				
				this.clientInfo.getConnectionInfo().getClientSocket().receive(packet);
				String received = new String(packet.getData(),0, packet.getLength(),CryptoLibrary.CHARSET);
				
				MessageHandler handler = new MessageHandler(this, received, packet.getAddress(), packet.getPort());
				(new Thread(handler)).start();
			}
		}catch(Exception e){
			System.out.println("Exception :" + e);
			e.printStackTrace();
			return;
		} finally{
			if(!clientInfo.getConnectionInfo().getClientSocket().isClosed()){
				this.clientInfo.getConnectionInfo().getClientSocket().close();
			}
		}
	}
	
	public void sendMessage(String peername, String message){
		PeerInfo peerInfo = this.peers.getPeerByUserName(peername);

		if (peerInfo == null) {
			System.out.println(peername + "is not online anymore");
			return;
		}
		String[] messageParams = new String[2];
		messageParams[0] = this.clientInfo.getUserId().toString();
		
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
		this.clientInfo.sendMessage(HeaderHandler.pack(messageParams), MessageType.CLIENT_CLIENT_MESSAGE, peerInfo.getPeerIp(), peerInfo.getPeerPort());
	}
	
	public void logout(){
		this.running = true;
		this.clientInfo.destoryKeys();
		this.peers.clear();
	}
}
