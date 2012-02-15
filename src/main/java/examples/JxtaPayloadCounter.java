package examples;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.tcpip.Jxta;
import org.jnetpcap.protocol.tcpip.Jxta.JxtaMessageType;
import org.jnetpcap.protocol.tcpip.Tcp;

public class JxtaPayloadCounter {

	public static float tWireLen = 0;
	public static float tPayloadLen = 0;

	/**
	 * @param args
	 */
	public static void main(String[] args) {		
		final Jxta jxta = new Jxta();

		final String FILENAME = "/home/thiago/tmp/pcap-traces/jxta-sample.pcap";
		//		final String FILENAME = "/home/thiago/tmp/pcap-traces/jxta-mcast-sample.pcap";
		final StringBuilder errbuf = new StringBuilder();

		final Pcap pcap = Pcap.openOffline(FILENAME, errbuf);

		pcap.loop(Pcap.LOOP_INFINITE, new JPacketHandler<StringBuilder>() {

			public void nextPacket(JPacket packet, StringBuilder errbuf) {
				System.out.println("\nFrame: " + packet.getFrameNumber());
				if(packet.hasHeader(Tcp.ID)){
					Tcp tcp = new Tcp();
					packet.getHeader(jxta);
					packet.getHeader(tcp);
					System.out.println("TcpLen=" + tcp.getLength() + ", PayloadLen=" + tcp.getPayloadLength());
					if (packet.hasHeader(Jxta.ID)) {
						if(jxta.getJxtaMessageType() == JxtaMessageType.WELCOME){
							System.out.println("JxtaWelcomeLen=" + jxta.getRawWelcome().length);
						}else
							if(jxta.getJxtaMessageType() == JxtaMessageType.DEFAULT){
								System.out.println("JxtaHeaderLen=" + jxta.getRawHeader().length);
								jxta.decodeMessage();
								System.out.println("JxtaContentLen=" + jxta.getRawContent().length);
							}
					}
				}
			}
		}, errbuf);
	}
}