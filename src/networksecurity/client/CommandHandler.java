package networksecurity.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class CommandHandler implements Runnable {

	private ClientInfo client;
	private DatagramSocket outSocket;
	private InetAddress serverIp;
	private int serverPort;

	public CommandHandler(ClientInfo client, DatagramSocket outSocket,
			InetAddress serverIp, int port) {
		// TODO Auto-generated constructor stub
		this.client = client;
		this.outSocket = outSocket;
		this.serverIp = serverIp;
		this.serverPort = port;
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

				} else if (argsStrings[0].toUpperCase().equals(
						CommandType.LOGOUT.toString())) {

				} else if (argsStrings[0].toUpperCase().equals(
						CommandType.SEND.toString())) {
					System.out
							.print("Please don't waste resources by sending empty message");
				} else {
					System.out.println("CommandNotSupported. Try these [list | logout | send <message>]");
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
}