package examples.packetgen;

import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.URI;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.logging.Level;

import net.jxta.exception.PeerGroupException;
import net.jxta.id.IDFactory;
import net.jxta.logging.Logging;
import net.jxta.peer.PeerID;
import net.jxta.peergroup.PeerGroup;
import net.jxta.peergroup.PeerGroupID;
import net.jxta.platform.NetworkConfigurator;
import net.jxta.platform.NetworkManager;
import net.jxta.socket.JxtaSocket;

public class MySimpleClient { 

	private static long ITERATIONS = 1;	
	private static long RUNS = 2;
	private static int PAYLOADSIZE = 1024;

	private static String clientName = "MySimpleClient";
	public static final File confFile = new File("." + System.getProperty("file.separator") + clientName);
	public static final PeerID peerId = IDFactory.newPeerID(PeerGroupID.defaultNetPeerGroupID, clientName.getBytes());
	private static String rdvAddress = null;
	private transient NetworkManager netManager = null;
	private transient PeerGroup netPeerGroup = null;

	public MySimpleClient(boolean waitForRendezvous) {
		try {
			NetworkManager.RecursiveDelete(confFile);
			netManager = new NetworkManager(NetworkManager.ConfigMode.EDGE, clientName, confFile.toURI());			
			NetworkConfigurator netConfigurator = netManager.getConfigurator();

			netConfigurator.clearRendezvousSeeds();
			String address = null;
			if(rdvAddress == null)
				address = "tcp://" + InetAddress.getLocalHost().getHostAddress() + ":" + MySimpleServer.tcpPort;
			else
				address = "tcp://" + rdvAddress;
			URI rdzvUri = URI.create(address);
			netConfigurator.addSeedRendezvous(rdzvUri);

			netConfigurator.setTcpPort(9722);
			netConfigurator.setTcpEnabled(true);
			netConfigurator.setTcpIncoming(true);
			netConfigurator.setTcpOutgoing(true);
			netConfigurator.setPeerID(peerId);
			netConfigurator.save();			

			netPeerGroup = netManager.startNetwork();
		} catch (IOException e) {
			e.printStackTrace();
		}catch (PeerGroupException e) {
			e.printStackTrace();
		}

		netPeerGroup.getRendezVousService().setAutoStart(false);
		if (netManager.waitForRendezvousConnection(120000)) {
            System.out.println("### Connected");
        } else {
        	System.out.println("### Connection Error!!");
        }
	}

	public void run(int size) {
		try {
			long start = System.currentTimeMillis();
			System.out.println("### Connecting to the server");

			JxtaSocket socket = new JxtaSocket(netPeerGroup, null, MySimpleServer.createSocketAdvertisement(), 60000, true);
			socket.setSoTimeout(5 * 60 * 1000);
			
			OutputStream out = socket.getOutputStream();
			DataOutput dos = new DataOutputStream(out);
			dos.writeInt(size);

			byte[] buffer = new byte[size];

			Arrays.fill(buffer, (byte) 2);
			out.write(buffer);
			out.flush();
			out.close();

			long finish = System.currentTimeMillis();
			long elapsed = finish - start;

			System.out.println(MessageFormat.format("### {0} bytes in {1} ms. Throughput = {2} KB/sec.", size, elapsed,(size / elapsed) * 1000 / 1024));			
			socket.close();
			System.out.println("### Socket connection closed");
			
		} catch (Exception io) {
			io.printStackTrace();
		}
	}

	private void stop() {
		netManager.stopNetwork();
	}

	public static void main(String args[]) {
		int i = 1;
		int k = 1;
		System.setProperty(Logging.JXTA_LOGGING_PROPERTY, Level.SEVERE.toString());

		// Parameters
		if(args.length == 4){
			ITERATIONS = Integer.valueOf(args[0]).intValue();
			RUNS = Integer.valueOf(args[1]).intValue();
			PAYLOADSIZE = Integer.valueOf(args[2]).intValue() * 1024;
			rdvAddress = args[3];
		}

		try {
			Thread.currentThread().setName(MySimpleClient.class.getName() + ".main()");			
			boolean waitForRendezvous = true;
			MySimpleClient jxtaPeer = new MySimpleClient(waitForRendezvous);

			for (int j = 0; j < ITERATIONS; j++) {
				for (; i <= RUNS; i++) {
					System.out.println("\n### Sending #" + k++);
					jxtaPeer.run(PAYLOADSIZE);
				}
				PAYLOADSIZE = PAYLOADSIZE * 1024;
				i = 1;
			}			
			jxtaPeer.stop();

		} catch (Throwable e) {
			e.printStackTrace();
		}
	}
}
