package networksecurity.client;

import java.io.File;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;

import networksecurity.common.*;
import networksecurity.common.ConfigReader.ConfigReaderException;

public class Client {

	private static ClientInfo clientInfo = null;

	/* starting point of the client */
	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		try {
			System.out.println(new File(".").getCanonicalPath());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		String configFile = "src/networksecurity/resources/client.cfg";
		if (args.length == 1) {
			configFile = args[0];
		}

		ClientConfigReader configReader;
		try {
			configReader = new ClientConfigReader(configFile);
		} catch (ConfigReaderException e) {
			System.out.println("Unable to read config file");
			throw new RuntimeException(e);
		}

		clientInfo = new ClientInfo(configReader);
		clientInfo.loginPrompt();

		clientInfo.setClientSocket(new DatagramSocket(clientInfo
				.getClientPort()));

		String message = MessageType.CLIENT_SERVER_HELLO.createMessage("HELLO");
		byte[] messageBytes = message.getBytes(CryptoHelper.CHARSET);

		DatagramPacket packet = new DatagramPacket(messageBytes,
				messageBytes.length, clientInfo.getServerIp(),
				clientInfo.getServerPort());

		clientInfo.getClientSocket().send(packet);

		run();
	}

	public static void run(){
		byte[] buf = new byte[1024];
		boolean running = true;
		
		/* Start listenening */
		try{
			
			DatagramPacket packet = new DatagramPacket(buf, buf.length);
			
			while(running){
				
				clientInfo.getClientSocket().receive(packet);
				String received = new String(packet.getData(),0, packet.getLength(),CryptoHelper.CHARSET);
				
				MessageHandler handler = new MessageHandler(clientInfo, received, packet.getAddress(), packet.getPort(),
						clientInfo.getClientSocket());
				(new Thread(handler)).start();
			}
		}catch(Exception e){
			System.out.println("Exception :" + e);
		}
	}
}
