//package examples;
//import java.io.ByteArrayOutputStream;
//import java.io.IOException;
//import java.nio.BufferUnderflowException;
//import java.nio.ByteBuffer;
//import java.util.ArrayList;
//import java.util.HashMap;
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
//
//public class JxtaFlowUtil {
//
//	// JXTA namespaces and delimiters
//	private static final String socketNamespace = "JXTASOC";
//	private static final String reqPipeTag = "reqPipe";
//	private static final String remPipeTag = "remPipe";	
//	private static final String closeTag = "close";
//
//	public static HashMap<Integer,ArrayList<Jxta>> generateSocketFlows(final StringBuilder errbuf, final Pcap pcap) {
//		final HashMap<Integer,Jxta> fragments = new HashMap<Integer,Jxta>();
//		final HashMap<Integer,ArrayList<Jxta>> socketFlows = new HashMap<Integer,ArrayList<Jxta>>(); 
//
//		pcap.loop(Pcap.LOOP_INFINITE, new JPacketHandler<StringBuilder>() {
//			Tcp tcp = new Tcp();
//			Jxta jxta = new Jxta();
//
//			public void nextPacket(JPacket packet, StringBuilder errbuf) {
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
//								updateStatistics(packet,jxta,socketFlows);
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
//										updateStatistics(packet, jxta, socketFlows);
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
//								updateStatistics(packet, jxta, socketFlows);
//								if(jxta.isFragmented()){
//									jxta.decode(ByteBuffer.wrap(jxta.getRemain()));									
//									updateStatistics(packet, jxta, socketFlows);
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
//		return socketFlows;
//	}
//	
//
//	public static void updateSocketFlows(Jxta jxta, HashMap<Integer,ArrayList<Jxta>> socketFlows){
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
//
//	public static void updateStatistics(JPacket packet, Jxta jxta, HashMap<Integer,ArrayList<Jxta>> socketFlows){
//		jxta.getJxtaPackets().add(packet);
//		updateSocketFlows(jxta, socketFlows);
//	}
//
//}
