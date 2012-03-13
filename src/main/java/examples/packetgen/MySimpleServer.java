package examples.packetgen;

import java.io.DataInput;
import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.text.MessageFormat;
import java.util.logging.Level;

import net.jxta.document.AdvertisementFactory;
import net.jxta.exception.PeerGroupException;
import net.jxta.id.IDFactory;
import net.jxta.logging.Logging;
import net.jxta.peer.PeerID;
import net.jxta.peergroup.PeerGroup;
import net.jxta.peergroup.PeerGroupID;
import net.jxta.pipe.PipeID;
import net.jxta.pipe.PipeService;
import net.jxta.platform.NetworkConfigurator;
import net.jxta.platform.NetworkManager;
import net.jxta.protocol.PipeAdvertisement;
import net.jxta.socket.JxtaServerSocket;

public class MySimpleServer {

	private static String serverName = "MySocketServer";
	private transient PeerGroup netPeerGroup = null;
	public static final PeerID peerId = IDFactory.newPeerID(PeerGroupID.defaultNetPeerGroupID, serverName.getBytes());
	public static final int tcpPort = 9723;
	public static final File confFile = new File("." + System.getProperty("file.separator") + serverName);

	
	public MySimpleServer() throws IOException, PeerGroupException {
		NetworkManager.RecursiveDelete(confFile);
		NetworkManager netManager = new NetworkManager(NetworkManager.ConfigMode.RENDEZVOUS, serverName, confFile.toURI());
		NetworkConfigurator netConfigurator = netManager.getConfigurator();
        
        netConfigurator.setTcpPort(tcpPort);
        netConfigurator.setTcpEnabled(true);
        netConfigurator.setTcpIncoming(true);
        netConfigurator.setTcpOutgoing(true);
        netConfigurator.setPeerID(peerId);
        netConfigurator.save();

		netManager.startNetwork();
				
		netPeerGroup = netManager.startNetwork();
	}

	public static PipeAdvertisement createSocketAdvertisement() {
		PipeAdvertisement advertisement = (PipeAdvertisement) AdvertisementFactory.newAdvertisement(PipeAdvertisement.getAdvertisementType());
        PipeID pipeId = IDFactory.newPipeID(PeerGroupID.defaultNetPeerGroupID, serverName.getBytes());

		advertisement.setPipeID(pipeId);
		advertisement.setType(PipeService.UnicastType);
		advertisement.setName("Unicast Socket");
		return advertisement;
	}

	public void run() {
		System.out.println("### Starting MySimpleServer");
		JxtaServerSocket serverSocket = null;
		
		try {
			PipeAdvertisement pipeAdv = createSocketAdvertisement();
			serverSocket = new JxtaServerSocket(netPeerGroup, pipeAdv, 200, 60000);
		} catch (Exception e) {
			e.printStackTrace();
		}

		int i = 1;
		while (true) {
			try {
				System.out.println("### Waiting for connections");
				Socket socket = serverSocket.accept();		
				socket.setSoTimeout(5 * 60 * 1000);
				if (socket != null) {
					System.out.println("\n### Receiving #" + i++);
					System.out.println("### New socket connection accepted");
					Thread thread = new Thread(new ConnectionHandler(socket), "Connection Handler Thread");
					thread.start();
				}
			} catch (Exception e) {
				e.printStackTrace(); 
			}
		}
	}

	private class ConnectionHandler implements Runnable {
		Socket socket = null;

		ConnectionHandler(Socket socket) {
			this.socket = socket;
		}

		private void receiveData(Socket socket) {
			try {
				long start = System.currentTimeMillis();

				InputStream in = socket.getInputStream();
				DataInput dis = new DataInputStream(in);

				int size = dis.readInt();

				byte[] buf = new byte[size];
				dis.readFully(buf);
				in.close();

				long finish = System.currentTimeMillis();
				long elapsed = finish - start;
				if(elapsed <= 0){
					elapsed = 1;
				}
				
				System.out.println(MessageFormat.format("### {0} bytes in {1} ms. Throughput = {2} KB/sec.", size, elapsed,(size / elapsed) * 1000 / 1024));
				
				socket.close();								
				System.out.println("### Connection closed");
				
			} catch (Exception ie) {
				ie.printStackTrace();
			} 
		}

		public void run() {
			receiveData(socket);
		}
	}

	public static void main(String args[]) {
		System.setProperty(Logging.JXTA_LOGGING_PROPERTY, Level.SEVERE.toString());		
		try {
			Thread.currentThread().setName(MySimpleServer.class.getName() + ".main()");
			MySimpleServer socEx = new MySimpleServer();
			socEx.run();
		} catch (Throwable e) {
			e.printStackTrace();
		}
	}
}
