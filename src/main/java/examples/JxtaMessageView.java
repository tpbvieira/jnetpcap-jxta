package examples;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

import net.jxta.endpoint.Message;
import net.jxta.endpoint.Message.ElementIterator;
import net.jxta.endpoint.MessageElement;
import net.jxta.impl.endpoint.router.EndpointRouterMessage;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Jxta;
import org.jnetpcap.protocol.tcpip.Jxta.JxtaMessageType;
import org.jnetpcap.protocol.tcpip.Tcp;

public class JxtaMessageView {

	public static HashMap<Integer,Jxta> frags = new HashMap<Integer,Jxta>();

	public static void main(String[] args) {
//		final String FILENAME = "/home/thiago/tmp/pcap-traces/jxta-socket/simpleSocket/1/1.1.1/1.1.1.pcap";
		final String FILENAME = "/home/thiago/tmp/pcap-traces/jxta-socket/simpleSocket/1024/1.1.1024/1.1.1024.pcap";

		final StringBuilder errbuf = new StringBuilder();
		final Pcap pcap = Pcap.openOffline(FILENAME, errbuf);

		pcap.loop(Pcap.LOOP_INFINITE, new JPacketHandler<StringBuilder>() {					

			Tcp tcp = new Tcp();
			Jxta jxta = new Jxta();

			public void nextPacket(JPacket packet, StringBuilder errbuf) {				

				if(packet.hasHeader(Tcp.ID)){
					packet.getHeader(tcp);

					// Looking for tcp fragmentation 
					if(frags.size() > 0 && tcp.getPayloadLength() > 0){
						System.out.println("\n### Frame: " + packet.getFrameNumber());

						Ip4 ip = new Ip4();
						packet.getHeader(ip);

						// id = IP and port of source and destiny
						int[] id = getFlowId(ip,tcp);
						jxta = frags.get(Arrays.hashCode(id));
						
						if(jxta != null){
							// writes actual payload into last payload
							ByteArrayOutputStream buffer = new ByteArrayOutputStream();
							buffer.write(jxta.getJxtaPayload(), 0, jxta.getJxtaPayload().length);					
							buffer.write(tcp.getPayload(), 0, tcp.getPayload().length);
							ByteBuffer bb = ByteBuffer.wrap(buffer.toByteArray());
							System.out.println("## Buffer = " + bb.array().length);
							try{
								jxta.decode(bb);
								if(frags.remove(Arrays.hashCode(id)) == null){
									throw new RuntimeException("### Error: Flow id not found");
								}
								tcpFlagsPrettyPrint(tcp);
								messagePrettyPrint(jxta);	

								if(bb.hasRemaining()){// if there are bytes, tries parser a full message with it									
									System.out.println("### There are still bytes: " + bb.remaining());									
									try{
										packet.hasHeader(tcp);
										byte[] resto = new byte[bb.remaining()];
										bb.get(resto, 0, bb.remaining());
										jxta.decode(ByteBuffer.wrap(resto));
										messagePrettyPrint(jxta);										
										tcpFlagsPrettyPrint(tcp);									
									}catch(BufferUnderflowException e ){
										ArrayList<JPacket> packets = jxta.getPackets();
										packets.clear();
										packets.add(packet);
										frags.put(Arrays.hashCode(id),jxta);
										System.out.println("### Queued again... " + Arrays.hashCode(id));										
									}catch (IOException failed) {
										ArrayList<JPacket> packets = jxta.getPackets();
										packets.clear();
										packets.add(packet);
										frags.put(Arrays.hashCode(id),jxta);
										System.out.println("### Queued again... " + Arrays.hashCode(id));
									}catch (Exception e) {
										System.out.println("### Erro inesperado");
										e.printStackTrace();
									}

									return;
								}															
							}catch(BufferUnderflowException e ){								
								jxta.getPackets().add(packet);
								frags.put(Arrays.hashCode(id), jxta);
								System.out.println("### Fragmented updated " + Arrays.hashCode(id));
							}catch (IOException failed) {
								jxta.getPackets().add(packet);
								frags.put(Arrays.hashCode(id), jxta);
								System.out.println("### Fragmented updated " + Arrays.hashCode(id));
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
								int[] id = getFlowId(ip,tcp);								
								jxta.setFragmented(true);
								jxta.getPackets().add(packet);
								frags.put(Arrays.hashCode(id),jxta);
								System.out.println("## Queued " + Arrays.hashCode(id));
								tcpFlagsPrettyPrint(tcp);
							}catch(IOException e){
								Ip4 ip = new Ip4();
								packet.getHeader(ip);
								int[] id = getFlowId(ip,tcp);	
								jxta.setFragmented(true);
								jxta.getPackets().add(packet);
								frags.put(Arrays.hashCode(id),jxta);
								System.out.println("## Queued " + Arrays.hashCode(id));
								tcpFlagsPrettyPrint(tcp);
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

		System.out.println("\n### " + frags.size() + " JXTA reassembly error");
	}

	public static int[] getFlowId(Ip4 ip, Tcp tcp) {
		int[] id = new int[10];
		byte[] src = ip.source();
		byte[] dst = ip.destination();						
		id[0] = src[0];
		id[1] = src[1];
		id[2] = src[2];
		id[3] = src[3];
		id[4] = tcp.source();
		id[5] = dst[0];
		id[6] = dst[1];
		id[7] = dst[2];
		id[8] = dst[3];
		id[9] = tcp.destination();
		return id;
	}

	public static void tcpFlagsPrettyPrint(Tcp tcp) {
		//				System.out.println("## Psh: " + tcp.flags_PSH());
		//				System.out.println("## Ack: " + tcp.flags_ACK());
		//				System.out.println("## Seq: " + tcp.seq());
		//				System.out.println("## Nxt: " + tcp.ack());
	}
	
	private static void welcomePrettyPrint(Jxta jxta){
		System.out.println("### Welcome");
		System.out.println(new String(jxta.getJxtaPayload()));
	}

	public static void messagePrettyPrint(Jxta jxta){
		Message msg = jxta.getMessage();
		System.out.println("\n### Message");
		ArrayList<JPacket> pkts = jxta.getPackets();
		if(pkts != null && pkts.size() > 0){
			System.out.print("### Reassembled with:");
			for (JPacket pkt : pkts) {
				System.out.print(" " + pkt.getFrameNumber());
			}
			System.out.println();
		}				
		
//		 Namespaces		
//		Iterator<String> it = msg.getMessageNamespaces();
//		while(it.hasNext()){
//			System.out.println(it.next());
//		}
		
		// Source and Destination
		EndpointRouterMessage erm = new EndpointRouterMessage(msg,false);
		System.out.println("### From: " + erm.getSrcAddress());
		System.out.println("### To: " + erm.getDestAddress());		

		// Elements
		ElementIterator elements = msg.getMessageElements();
		while(elements.hasNext()){
			MessageElement elem = elements.next();	
			System.out.println("ElementName=" + elem.getElementName());			
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
		}
	}
}