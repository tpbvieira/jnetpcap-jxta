package drivers;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.HashMap;

import net.jxta.parser.JxtaParser;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.tcpip.Jxta;
import org.jnetpcap.protocol.tcpip.Jxta.JxtaMessageType;
import org.jnetpcap.protocol.tcpip.Tcp;

/**
 * Counts the number of frames, jxta messages, bytes of all frames and of jxta messages.
 * Calculates how many frames and bytes are processed per second, and the relation between jxta payload and total bytes.
 * 
 * @author Thiago Vieira
 *
 */

public class JxtaCountDriver {

	public static HashMap<Long,Jxta> tcpFrags = new HashMap<Long,Jxta>();
	private static float frames = 0;
	private static float size = 0;
	private static float jxtaMessages = 0;
	private static float jxtaPayload = 0;
	private static float tcpPayload = 0;

	public static void main(String[] args) {
		System.out.println("### JxtaCounts ###\n" );

		String fileName = "/home/thiago/tmp/_/128_server.1000.1.256.pcap";

		if(args != null && args.length > 0){
			fileName = args[0];
		}

		final StringBuilder errbuf = new StringBuilder();
		final Pcap pcap = Pcap.openOffline(fileName, errbuf);

		long t0 = System.currentTimeMillis();

		pcap.loop(Pcap.LOOP_INFINITE, new JPacketHandler<StringBuilder>() {

			Tcp tcp = new Tcp();
			Jxta jxta = new Jxta();			

			public void nextPacket(JPacket packet, StringBuilder errbuf) {
				frames++;
				size += packet.getPacketWirelen();
				
				boolean handled = false;

				if(packet.hasHeader(Tcp.ID)){
					packet.getHeader(tcp);
					tcpPayload += tcp.getPayloadLength();
					
					// Looking for tcp fragmentation 
					if(tcp.getPayloadLength() > 0 && tcpFrags.size() > 0){
						long frameNum = -1;

						for (Long id : tcpFrags.keySet()) {							
							Jxta frag = tcpFrags.get(id);							

							int headerLen = (int)frag.getHeaderMsg().getContentLengthHeader();
							byte[] tmp = frag.getJxtaPayload();
							byte[] rawMsg = new byte[tmp.length - headerLen];
							System.arraycopy(tmp, headerLen, rawMsg, 0, tmp.length - headerLen);

							byte[] pay = tcp.getPayload();
							byte[] buf = new byte[rawMsg.length + pay.length];

							System.arraycopy(rawMsg, 0, buf, 0, rawMsg.length);
							System.arraycopy(pay, 0, buf, rawMsg.length, pay.length);

							try{
								JxtaParser.processMessage(ByteBuffer.wrap(buf),jxta.getHeaderMessage());								
								frameNum = id.longValue();
								handled = true;
								jxtaMessages++;
								jxtaPayload+=pay.length;
								break;
							}catch(Exception e){
							}
						}
						if(frameNum != -1){
							tcpFrags.remove(Long.valueOf(frameNum));							
						}
					}

					if (!handled && packet.hasHeader(Jxta.ID)) {
						packet.getHeader(jxta);
						jxtaMessages++;

						if(jxta.getJxtaMessageType() == JxtaMessageType.WELCOME){
							jxtaPayload+=jxta.getPayloadLength();
						}else
							if(jxta.getJxtaMessageType() == JxtaMessageType.DEFAULT){
								try{
									jxtaPayload+= jxta.getPayloadLength();
								}catch(BufferUnderflowException e ){
									tcpFrags.put(new Long(packet.getFrameNumber()),jxta);
								}
							}
					}
				}			

			}			

		}, errbuf);

		long t1 = System.currentTimeMillis();
		float seconds = (t1 - t0);
		System.out.println("### " + seconds + " ms to process" );
		System.out.println("### " + tcpFrags.size() + " JXTA reassembly error");
		System.out.println("### " + frames + " frames");
		System.out.println("### " + (size)/1024 + " KB total");
		System.out.println("### " + (size*8)/1024 + " Kb total");
		System.out.println("### " + ((size*8)/1024)/1024 + " Mb total");
		System.out.println("### " + (jxtaPayload)/1024 + " KB jxtaPayload");
		System.out.println("### " + (tcpPayload)/1024 + " KB tcpPayload");
		System.out.println();
		System.out.println("### " + Float.valueOf(frames/seconds) + " frames/ms" );
		System.out.println("### " + Float.valueOf(jxtaMessages/seconds) + " JxtaMsg/ms" );
		System.out.println("### " + Float.valueOf((((size)/1024)/1024)/seconds) + " MB/ms" );
		System.out.println("### " + Float.valueOf((((size*8)/1024)/1024)/seconds) + " Mb/ms" );
		System.out.println("### " + Float.valueOf((jxtaPayload/tcpPayload)/100) + " % of efficiency" );
	}
}