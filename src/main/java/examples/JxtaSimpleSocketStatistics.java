//package examples;
//
//import java.io.ByteArrayOutputStream;
//import java.io.IOException;
//import java.nio.BufferUnderflowException;
//import java.nio.ByteBuffer;
//import java.util.ArrayList;
//import java.util.HashMap;
//import java.util.Set;
//
//import net.jxta.document.AdvertisementFactory;
//import net.jxta.document.StructuredDocumentFactory;
//import net.jxta.document.XMLDocument;
//import net.jxta.endpoint.Message;
//import net.jxta.endpoint.Message.ElementIterator;
//import net.jxta.endpoint.MessageElement;
//import net.jxta.impl.endpoint.router.EndpointRouterMessage;
//import net.jxta.impl.util.pipe.reliable.Defs;
//import net.jxta.protocol.PipeAdvertisement;
//
//import org.jnetpcap.Pcap;
//import org.jnetpcap.packet.JPacket;
//import org.jnetpcap.packet.JPacketHandler;
//import org.jnetpcap.protocol.network.Ip4;
//import org.jnetpcap.protocol.tcpip.Jxta;
//import org.jnetpcap.protocol.tcpip.Jxta.JxtaMessageType;
//import org.jnetpcap.protocol.tcpip.JxtaUtils;
//import org.jnetpcap.protocol.tcpip.Tcp;
//
//public class JxtaSimpleSocketStatistics {
//
//	// JXTA namespaces and delimiters
//	private static final String socketNamespace = "JXTASOC";
//	private static final String reqPipeTag = "reqPipe";
//	private static final String remPipeTag = "remPipe";	
//	protected static final String closeTag = "close";
//
//	private static float frames = 0;
//	private static float totalSize = 0;
//	private static float tcpPayload = 0;
//	private static float jxtaPayload = 0;	
//
//	public static HashMap<Integer,Jxta> fragments = new HashMap<Integer,Jxta>();
//	private static HashMap<Integer,ArrayList<Jxta>> socketFlows = new HashMap<Integer,ArrayList<Jxta>>(); 
//
//	public static void main(String[] args) {
//		final String FILENAME = "/home/thiago/tmp/_/client.1.03.1024.pcap";
//
//		final StringBuilder errbuf = new StringBuilder();
//		final Pcap pcap = Pcap.openOffline(FILENAME, errbuf);
//		long t0 = System.currentTimeMillis();
//
//		pcap.loop(Pcap.LOOP_INFINITE, new JPacketHandler<StringBuilder>() {					
//
//			Tcp tcp = new Tcp();
//			Jxta jxta = new Jxta();
//
//			public void nextPacket(JPacket packet, StringBuilder errbuf) {				
//				frames++;
//				totalSize += packet.getPacketWirelen();
//
//				if(packet.hasHeader(Tcp.ID)){
//					packet.getHeader(tcp);
//
//					// Looking for tcp fragmentation 
//					if(fragments.size() > 0 && tcp.getPayloadLength() > 0){
//						Ip4 ip = new Ip4();
//						packet.getHeader(ip);
//						int id = JxtaUtils.getFlowId(ip,tcp);
//						jxta = fragments.get(id);
//
//						if(jxta != null){
//							// writes actual payload into last payload
//							ByteArrayOutputStream buffer = new ByteArrayOutputStream();
//							buffer.write(jxta.getJxtaPayload(), 0, jxta.getJxtaPayload().length);					
//							buffer.write(tcp.getPayload(), 0, tcp.getPayload().length);
//							ByteBuffer bb = ByteBuffer.wrap(buffer.toByteArray());
//							try{
//								jxta.decode(bb);								
//								updateStatistics(packet,jxta);
//								fragments.remove(id);
//
//								if(bb.hasRemaining()){
//									try{
//										jxta = new Jxta();
//										packet.getHeader(jxta);
//
//										byte[] resto = new byte[bb.remaining()];
//										bb.get(resto, 0, bb.remaining());
//										jxta.decode(ByteBuffer.wrap(resto));										
//										updateStatistics(packet, jxta);
//									}catch(BufferUnderflowException e ){
//										ArrayList<JPacket> packets = jxta.getJxtaPackets();
//										packets.clear();
//										packets.add(packet);
//										fragments.put(id,jxta);										
//									}catch (IOException failed) {
//										ArrayList<JPacket> packets = jxta.getJxtaPackets();
//										packets.clear();
//										packets.add(packet);
//										fragments.put(id,jxta);
//									}
//									return;
//								}															
//							}catch(BufferUnderflowException e ){								
//								jxta.getJxtaPackets().add(packet);
//								fragments.put(id, jxta);
//							}catch (IOException failed) {
//								jxta.getJxtaPackets().add(packet);
//								fragments.put(id, jxta);
//							}
//							return;
//						}
//					}
//
//					// the new packet payload is a Jxta message
//					if (packet.hasHeader(Jxta.ID)) {
//						jxta = new Jxta();
//						packet.getHeader(jxta);
//						if(jxta.getJxtaMessageType() == JxtaMessageType.DEFAULT){
//							try{									
//								jxta.decodeMessage();								
//								updateStatistics(packet, jxta);
//								if(jxta.isFragmented()){
//									jxta.decode(ByteBuffer.wrap(jxta.getRemain()));									
//									updateStatistics(packet, jxta);
//								}
//							}catch(BufferUnderflowException e ){								
//								Ip4 ip = new Ip4();
//								packet.getHeader(ip);
//								int id = JxtaUtils.getFlowId(ip,tcp);								
//								jxta.setFragmented(true);
//								jxta.getJxtaPackets().add(packet);
//								fragments.put(id,jxta);
//							}catch(IOException e){
//								Ip4 ip = new Ip4();
//								packet.getHeader(ip);
//								int id = JxtaUtils.getFlowId(ip,tcp);	
//								jxta.setFragmented(true);
//								jxta.getJxtaPackets().add(packet);
//								fragments.put(id,jxta);
//							}
//						}else
//							if(jxta.getJxtaMessageType() == JxtaMessageType.WELCOME){
//								try{
//									// ??
//								}catch(Exception e){
//									throw new RuntimeException(e);
//								}
//							}
//					}
//				}
//			}
//
//		}, errbuf);
//
//		long flowTime = System.currentTimeMillis() - t0; 
//
//		System.out.println("\n### " + fragments.size() + " JXTA reassembly error");
//		System.out.println("### Flow Process Time: " + flowTime);
//		System.out.println("###");
//		System.out.println("### Frames: " + frames);
//		System.out.println("### Total: " + (totalSize)/1024 + " KB");
//		System.out.println("### TCP Payload: " + tcpPayload/1024 + " KB");
//		System.out.println("### JXTA Payload: " + jxtaPayload/1024 + " KB");
//		System.out.println("### JXTA Overhead: " + ((tcpPayload - jxtaPayload)/jxtaPayload) * 100 + " %");
//
//		Set<Integer> keys = socketFlows.keySet();
//		int i = 0;
//		for (Integer key : keys) {
//			System.out.println("\n\n### Flow: " + (++i));
//			printFlowStatistics(socketFlows.get(key));
//		}
//		
//		long totalTime = System.currentTimeMillis() - t0;
//		System.out.println("\n### Process Time: " + totalTime);
//	}
//
//	private static void printFlowStatistics(ArrayList<Jxta> flow){
//		double tcpPay = 0;
//		double jxtaPay = 0;
//		double tmp = 0, t0 = Long.MAX_VALUE, t1 = Long.MIN_VALUE, time = 0;
//
//		for (Jxta jxta : flow) {
//
//			ElementIterator it = jxta.getMessage().getMessageElements();
//			System.out.print("[");
//			while(it.hasNext()){
//				System.out.print(it.next().getElementName());
//				if(it.hasNext())
//					System.out.print(", ");
//			}
//			System.out.println("]");
//
//			tcpPay += jxta.getJxtaPayload().length;
//			jxtaPay += JxtaUtils.getMessageContent(jxta).length;
//
//			ArrayList<JPacket> pkts = jxta.getJxtaPackets();
//			if(pkts != null && pkts.size() > 0){
//				for (JPacket pkt : pkts) {
//					tmp = pkt.getCaptureHeader().timestampInMillis();				
//					if(tmp < t0)
//						t0 = tmp;
//					if(tmp > t1)
//						t1 = tmp;
//				}
//			}else{
//				tmp = jxta.getPacket().getCaptureHeader().timestampInMillis();				
//				if(tmp < t0)
//					t0 = tmp;				
//				if(tmp > t1)
//					t1 = tmp;
//			}
//
//		}
//
//		time = t1 - t0;
//		if(time == 0)
//			time = 1;
//
//		try{
//			System.out.println("### TCP Payload: " + (tcpPay)/1024 + " KB");
//			System.out.println("### JXTA Payload: " + (jxtaPay)/1024 + " KB");
//			System.out.println("### Transfer Time: " + time);
//			System.out.println("### T0: " + t0);
//			System.out.println("### T1: " + t1);
//			System.out.println("### JXTA Throughput: " + (tcpPay/1024)/(time/1000) + " KB/s");
//			System.out.println("### JXTA Overhead: " + ((tcpPay - jxtaPay)/(jxtaPay)) * 100 + " %");
//		}catch(Exception e){
//			e.printStackTrace();
//		}
//	}
//
//	private static void updateSocketFlows(Jxta jxta){
//		MessageElement el = null, el1, el2;
//		ElementIterator elements1, elements2;
//		Message msg = jxta.getMessage();
//
//		try{
//			elements1 = msg.getMessageElements(Defs.NAMESPACE, Defs.MIME_TYPE_ACK);
//			elements2 = msg.getMessageElements(Defs.NAMESPACE, Defs.MIME_TYPE_BLOCK);
//			el = msg.getMessageElement(socketNamespace, closeTag);
//			if(elements1.hasNext() || elements2.hasNext() || el != null){
//				EndpointRouterMessage erm = new EndpointRouterMessage(msg,false);
//				String strPipeId = erm.getDestAddress().getServiceParameter();
//				Integer pipeId = Integer.valueOf(strPipeId.hashCode());
//
//				if(socketFlows.containsKey(pipeId)){
//					socketFlows.get(pipeId).add(jxta);
//				}else{
//					ArrayList<Jxta> flow = new ArrayList<Jxta>();
//					flow.add(jxta);
//					socketFlows.put(pipeId, flow);
//				}					
//			}else{
//				el1 = msg.getMessageElement(socketNamespace, reqPipeTag);
//				el2 = msg.getMessageElement(socketNamespace, remPipeTag);
//				if(el1 != null)
//					el = el1;
//				else
//					if(el2 != null)
//						el = el2;
//				if (el != null) {
//					@SuppressWarnings("rawtypes")
//					XMLDocument adv = (XMLDocument) StructuredDocumentFactory.newStructuredDocument(el);
//					PipeAdvertisement pipe = (PipeAdvertisement) AdvertisementFactory.newAdvertisement(adv);
//
//					String strPipeId = new String(pipe.getPipeID().toString());
//					Integer pipeId = Integer.valueOf(strPipeId.hashCode());
//
//					if(socketFlows.containsKey(pipeId)){
//						socketFlows.get(pipeId).add(jxta);
//					}else{
//						ArrayList<Jxta> flow = new ArrayList<Jxta>();
//						flow.add(jxta);
//						socketFlows.put(pipeId, flow);
//					}
//				}
//			}
//
//		} catch (IOException e) {
//			e.printStackTrace();
//		} catch (RuntimeException e) {
//			e.printStackTrace();
//		}
//	}
//	
//	private static void updateStatistics(JPacket packet, Jxta jxta){
//		jxta.getJxtaPackets().add(packet);
//		updateSocketFlows(jxta);
//		jxtaPayload += JxtaUtils.getMessageContent(jxta).length;
//		tcpPayload += jxta.getJxtaPayload().length;
//	}
//
//}