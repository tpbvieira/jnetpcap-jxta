package drivers;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Set;
import java.util.SortedMap;

import net.jxta.document.AdvertisementFactory;
import net.jxta.document.StructuredDocumentFactory;
import net.jxta.document.XMLDocument;
import net.jxta.endpoint.Message;
import net.jxta.endpoint.Message.ElementIterator;
import net.jxta.endpoint.MessageElement;
import net.jxta.impl.endpoint.router.EndpointRouterMessage;
import net.jxta.protocol.PipeAdvertisement;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Jxta;
import org.jnetpcap.protocol.tcpip.Jxta.JxtaMessageType;
import org.jnetpcap.protocol.tcpip.JxtaUtils;
import org.jnetpcap.protocol.tcpip.Tcp;

/**
 * Pretty prints all JXTA messages of a trace.
 * 
 * @author Thiago Vieira
 *
 */

public class JxtaMessageViewDriver {

	public static void main(String[] args) {
		long t0,t1;
		final String FILENAME = "/home/thiago/tmp/_/captura.pcap";
		final StringBuilder errbuf = new StringBuilder();
		t0 = System.currentTimeMillis();
		final Pcap pcap = Pcap.openOffline(FILENAME, errbuf);
		HashMap<Integer,Jxta> frags = generateFullSocketFlows(errbuf, pcap);
		pcap.close();
		t1 = System.currentTimeMillis();
		
		System.out.println("\n### " + frags.size() + " JXTA reassembly error");
		System.out.println("### Time: " + (t1-t0));
	}

	public static HashMap<Integer,Jxta> generateFullSocketFlows(final StringBuilder errbuf, final Pcap pcap) {

		final HashMap<Integer,Jxta> frags = new HashMap<Integer,Jxta>();

		pcap.loop(Pcap.LOOP_INFINITE, new JPacketHandler<StringBuilder>() {					

			Tcp tcp = new Tcp();
			Jxta jxta = new Jxta();

			public void nextPacket(JPacket packet, StringBuilder errbuf) {				

				if(packet.hasHeader(Tcp.ID)){
					packet.getHeader(tcp);
					long seqNumber = tcp.seq();

					// Looking for tcp fragmentation 
					if(frags.size() > 0 && tcp.getPayloadLength() > 0){
						System.out.println("\n### Frame: " + packet.getFrameNumber());

						Ip4 ip = new Ip4();
						packet.getHeader(ip);

						// id = IP and port of source and destiny
						int id = JxtaUtils.getFlowId(ip,tcp);
						jxta = frags.get(id);

						if(jxta != null){
							// writes actual payload into last payload
							ByteArrayOutputStream buffer = new ByteArrayOutputStream();
							buffer.write(jxta.getJxtaPayload(), 0, jxta.getJxtaPayload().length);					
							buffer.write(tcp.getPayload(), 0, tcp.getPayload().length);
							ByteBuffer bb = ByteBuffer.wrap(buffer.toByteArray());
							System.out.println("## Buffer = " + bb.array().length);
							try{
								jxta.decode(bb);
								if(frags.remove(id) == null){
									throw new RuntimeException("### Error: Flow id not found");
								}
								messagePrettyPrint(jxta);	

								if(bb.hasRemaining()){// if there are bytes, tries parser a full message with it									
									System.out.println("### There are still bytes: " + bb.remaining());									
									try{
										byte[] resto = new byte[bb.remaining()];
										bb.get(resto, 0, bb.remaining());
										jxta.decode(ByteBuffer.wrap(resto));
										messagePrettyPrint(jxta);									
									}catch(BufferUnderflowException e ){
										SortedMap<Long,JPacket> packets = jxta.getJxtaPackets();
										packets.clear();
										packets.put(seqNumber,packet);
										frags.put(id,jxta);
										System.out.println("### Queued again... " + id);										
									}catch (IOException failed) {
										SortedMap<Long,JPacket> packets = jxta.getJxtaPackets();
										packets.clear();
										packets.put(seqNumber,packet);
										frags.put(id,jxta);
										System.out.println("### Queued again... " + id);
									}catch (Exception e) {
										System.out.println("### Erro inesperado");
										e.printStackTrace();
									}
									return;
								}															
							}catch(BufferUnderflowException e ){								
								jxta.getJxtaPackets().put(seqNumber,packet);
								frags.put(id, jxta);
								System.out.println("### Fragmented updated " + id);
							}catch (IOException failed) {
								jxta.getJxtaPackets().put(seqNumber,packet);
								frags.put(id, jxta);
								System.out.println("### Fragmented updated " + id);
							}
							return;
						}
					}

					// the new packet payload is a Jxta message
					if (packet.hasHeader(Jxta.ID)) {
						jxta = new Jxta();
						packet.getHeader(jxta);
						System.out.println("\n### Frame: " + packet.getFrameNumber());
						if(jxta.getJxtaMessageType() == JxtaMessageType.DEFAULT){
							try{									
								jxta.decodeMessage();								
								messagePrettyPrint(jxta);
								if(jxta.isFragmented()){
									jxta.decode(ByteBuffer.wrap(jxta.getRemain()));
								}
							}catch(BufferUnderflowException e ){								
								Ip4 ip = new Ip4();
								packet.getHeader(ip);
								int id = JxtaUtils.getFlowId(ip,tcp);								
								jxta.setFragmented(true);
								jxta.getJxtaPackets().put(seqNumber,packet);
								frags.put(id,jxta);
								System.out.println("## Queued " + id);
							}catch(IOException e){
								Ip4 ip = new Ip4();
								packet.getHeader(ip);
								int id = JxtaUtils.getFlowId(ip,tcp);	
								jxta.setFragmented(true);
								jxta.getJxtaPackets().put(seqNumber,packet);
								frags.put(id,jxta);
								System.out.println("## Queued " + id);
							}
						}else
							if(jxta.getJxtaMessageType() == JxtaMessageType.WELCOME){
								try{
									welcomePrettyPrint(jxta);
								}catch(Exception e){
									throw new RuntimeException(e);
								}
							}
					}
				}
			}

		}, errbuf);

		return frags;

	}

	public static void welcomePrettyPrint(Jxta jxta){
		System.out.println("### Welcome");
		System.out.println(new String(jxta.getJxtaPayload()));
	}

	@SuppressWarnings("rawtypes")
	public static void messagePrettyPrint(Jxta jxta){
		Message msg = jxta.getMessage();
		System.out.println("\n### Message");
		double tmp = 0, t0 = Long.MAX_VALUE, t1 = Long.MIN_VALUE;

		SortedMap<Long,JPacket> pkts = jxta.getJxtaPackets();
		if(pkts != null && pkts.size() > 0){
			System.out.print("### Reassembled with:");
			Set<Long> keys = pkts.keySet();
			for (Long key : keys) {				
				JPacket pkt = pkts.get(key);
				tmp = pkt.getCaptureHeader().timestampInMillis();				
				if(tmp < t0)
					t0 = tmp;				
				if(tmp > t1)
					t1 = tmp;
				System.out.print(" " + pkt.getFrameNumber());
			}
			System.out.println();
		}else{
			t0 = t1 = jxta.getPacket().getCaptureHeader().timestampInMillis();
		}

		// Source and Destination
		EndpointRouterMessage erm = new EndpointRouterMessage(msg,false);
		System.out.println("### From: " + erm.getSrcAddress());
		System.out.println("### To: " + erm.getDestAddress());		

		// Elements
		ElementIterator elements = msg.getMessageElements();
		System.out.println(">>> "  + msg.getMessageElement("EndpointSourceAddress"));
		System.out.println(">>> "  + msg.getMessageElement("EndpointDestinationAddress"));
		while(elements.hasNext()){
			MessageElement elem = elements.next();

			System.out.println("[" + elem.getElementName() + "], [" + elem.getMimeType() + "]");			
			if(elem.getElementName().equals("ack")){
				int sackCount = ((int) elem.getByteLength() / 4) - 1;
				try {
					DataInputStream dis = new DataInputStream(elem.getStream());
					int seqack = dis.readInt();
					System.out.println("## SeqAck: " + seqack);
					int[] sacs = new int[sackCount];

					for (int eachSac = 0; eachSac < sackCount; eachSac++) {
						sacs[eachSac] = dis.readInt();
						System.out.println("## sack: " + sacs[eachSac]);
					}
					Arrays.sort(sacs);

				} catch (IOException e) {
					System.out.println("### Erro printing the message");
					e.printStackTrace();
				}catch(Exception e){
					System.out.println("### Unexpected erro printing the message");
					e.printStackTrace();
				}
			}
			
			if(elem.getElementName().equals("reqPipe")){				
				try {
					XMLDocument adv = (XMLDocument) StructuredDocumentFactory.newStructuredDocument(elem);
					PipeAdvertisement pipeAdv = (PipeAdvertisement) AdvertisementFactory.newAdvertisement(adv);					
					System.out.println("### reqPipeId = " + pipeAdv.getID());
				} catch (IOException e) {
					e.printStackTrace();
				}
				
			}
		}

		// Indicators
		System.out.println("### TCP Payload: " + jxta.getJxtaPayload().length);		
		System.out.println("### JXTA Payload: " + JxtaUtils.getMessageContent(jxta).length);
		System.out.println("### Transfer Time: " + (t1 - t0));
		System.out.println("### T0: " + t0);
		System.out.println("### T1: " + t1);
	}

}