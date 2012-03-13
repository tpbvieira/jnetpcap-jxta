package examples;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

import net.jxta.document.AdvertisementFactory;
import net.jxta.document.StructuredDocumentFactory;
import net.jxta.document.XMLDocument;
import net.jxta.endpoint.Message;
import net.jxta.endpoint.MessageElement;
import net.jxta.impl.endpoint.router.EndpointRouterMessage;
import net.jxta.impl.util.pipe.reliable.Defs;
import net.jxta.protocol.PipeAdvertisement;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Jxta;
import org.jnetpcap.protocol.tcpip.Jxta.JxtaMessageType;
import org.jnetpcap.protocol.tcpip.Tcp;

import sun.misc.IOUtils;

public class JxtaStatistics {

	private static final String MSG_ELEMENT_NAMESPACE = "JXTASOC";
//	private static final String credTag = "Cred";
	private static final String reqPipeTag = "reqPipe";
//	private static final String remPeerTag = "remPeer";
	private static final String remPipeTag = "remPipe";
//	private static final String dataTag = "data";
//	private static final String closeTag = "close";
//	private final static String closeReqValue = "close";
//	private final static String closeAckValue = "closeACK";
//	private static final String streamTag = "stream";

	public static HashMap<Integer,Jxta> frags = new HashMap<Integer,Jxta>();
	private static float frames = 0;
	private static float totalSize = 0;
	private static float tcpPayload = 0;
	private static float jxtaPayload = 0;	
//	private static float meantime = 0;
	//	private static ArrayList<JPacket> flowPackets = new ArrayList<JPacket>();
	private static HashMap<Integer,ArrayList<Jxta>> socketFlows = new HashMap<Integer,ArrayList<Jxta>>(); 

	public static void main(String[] args) {
		//		final String FILENAME = "/home/thiago/tmp/pcap-traces/jxta-socket/simpleSocket/1/1.1.1/1.1.1.pcap";
		final String FILENAME = "/home/thiago/tmp/pcap-traces/jxta-socket/simpleSocket/1024/1.1.1024/1.1.1024.pcap";

		final StringBuilder errbuf = new StringBuilder();
		final Pcap pcap = Pcap.openOffline(FILENAME, errbuf);
		long t0 = System.currentTimeMillis();

		pcap.loop(Pcap.LOOP_INFINITE, new JPacketHandler<StringBuilder>() {					

			Tcp tcp = new Tcp();
			Jxta jxta = new Jxta();

			public void nextPacket(JPacket packet, StringBuilder errbuf) {				
				frames++;
				totalSize += packet.getPacketWirelen();

				if(packet.hasHeader(Tcp.ID)){
					packet.getHeader(tcp);

					// Looking for tcp fragmentation 
					if(frags.size() > 0 && tcp.getPayloadLength() > 0){
						Ip4 ip = new Ip4();
						packet.getHeader(ip);
						int[] id = getFlowId(ip,tcp);

						jxta = frags.get(Arrays.hashCode(id));

						if(jxta != null){
							// writes actual payload into last payload
							ByteArrayOutputStream buffer = new ByteArrayOutputStream();
							buffer.write(jxta.getJxtaPayload(), 0, jxta.getJxtaPayload().length);					
							buffer.write(tcp.getPayload(), 0, tcp.getPayload().length);
							ByteBuffer bb = ByteBuffer.wrap(buffer.toByteArray());
							try{
								jxta.decode(bb);								
								updateAfterDecode(packet,jxta);
								if(frags.remove(Arrays.hashCode(id)) == null){
									throw new RuntimeException("### Error: Flow id not found");
								}

								if(bb.hasRemaining()){// if there are bytes, tries parser a full message with it									
									try{
										jxta = new Jxta();
										packet.getHeader(jxta);

										byte[] resto = new byte[bb.remaining()];
										bb.get(resto, 0, bb.remaining());
										jxta.decode(ByteBuffer.wrap(resto));										
										updateAfterDecode(packet, jxta);
									}catch(BufferUnderflowException e ){
										ArrayList<JPacket> packets = jxta.getPackets();
										packets.clear();
										packets.add(packet);
										frags.put(Arrays.hashCode(id),jxta);										
									}catch (IOException failed) {
										ArrayList<JPacket> packets = jxta.getPackets();
										packets.clear();
										packets.add(packet);
										frags.put(Arrays.hashCode(id),jxta);
									}catch (Exception e) {
										e.printStackTrace();
									}

									return;
								}															
							}catch(BufferUnderflowException e ){								
								jxta.getPackets().add(packet);
								frags.put(Arrays.hashCode(id), jxta);
							}catch (IOException failed) {
								jxta.getPackets().add(packet);
								frags.put(Arrays.hashCode(id), jxta);
							}
							return;
						}
					}

					// the new packet payload is a Jxta message
					if (packet.hasHeader(Jxta.ID)) {
						jxta = new Jxta();
						packet.getHeader(jxta);
						if(jxta.getJxtaMessageType() == JxtaMessageType.DEFAULT){
							try{									
								jxta.decodeMessage();								
								updateAfterDecode(packet, jxta);
								if(jxta.isFragmented()){
									jxta.decode(ByteBuffer.wrap(jxta.getRemain()));									
									updateAfterDecode(packet, jxta);
								}
							}catch(BufferUnderflowException e ){								
								Ip4 ip = new Ip4();
								packet.getHeader(ip);
								int[] id = getFlowId(ip,tcp);								
								jxta.setFragmented(true);
								jxta.getPackets().add(packet);
								frags.put(Arrays.hashCode(id),jxta);
							}catch(IOException e){
								Ip4 ip = new Ip4();
								packet.getHeader(ip);
								int[] id = getFlowId(ip,tcp);	
								jxta.setFragmented(true);
								jxta.getPackets().add(packet);
								frags.put(Arrays.hashCode(id),jxta);
							}
						}else
							if(jxta.getJxtaMessageType() == JxtaMessageType.WELCOME){
								try{

								}catch(Exception e){
									throw new RuntimeException(e);
								}
							}
					}
				}
			}

		}, errbuf);

		//		meantime = getPacketsMeanTime(flowPackets);		
		long time = System.currentTimeMillis() - t0; 

		System.out.println("\n### " + frags.size() + " JXTA reassembly error");
		System.out.println("### Execution Time: " + time);
		System.out.println("###");
		System.out.println("### Frames: " + frames);
		System.out.println("### Total: " + (totalSize)/1024 + " KB");
		System.out.println("### TCP Payload: " + tcpPayload/1024 + " KB");
		System.out.println("### JXTA Payload: " + jxtaPayload/1024 + " KB");
		//		System.out.println("### Transfer Time: " + meantime);
		//		System.out.println("### JXTA Throughput: " + (jxtaPayload/1024)/(meantime/1000) + " KB/s");
		System.out.println("### JXTA Overhead: " + ((tcpPayload - jxtaPayload)/jxtaPayload) * 100 + " %");
		System.out.println();
		System.out.println("### Flows");
		Set<Integer> keys = socketFlows.keySet();
		int i = 0;
		for (Integer key : keys) {
			System.out.println("\n\n### Flow: " + (++i));
			flowStatistics(socketFlows.get(key));
		}
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

	public static byte[] getMessageContent(Jxta jxta){
		byte[] bytes = new byte[0];
		Message msg = jxta.getMessage();
		Iterator<MessageElement> it = msg.getMessageElements(Defs.NAMESPACE, Defs.MIME_TYPE_BLOCK);

		if(it != null && it.hasNext()){
			while(it.hasNext()){											
				MessageElement el = it.next();
				try{
					bytes = IOUtils.readFully(el.getStream(), -1, false);					
				}catch(Exception e){
					e.printStackTrace();
				}
			}
		}		

		return bytes;
	}

	public static long getPacketsMeanTime(ArrayList<JPacket> pkts){
		long time = 0;

		if(pkts.size() > 1){
			long v, t0 = Long.MAX_VALUE, t1 = Long.MIN_VALUE;			
			for (JPacket pkt : pkts) {
				v = pkt.getCaptureHeader().timestampInMillis();				
				if(v < t0)
					t0 = v;				
				if(v > t1)
					t1 = v;
			}
			time = t1 - t0;			
		}

		return time;
	}

	private static void updateSocketFlows(Jxta jxta){
		MessageElement el = null;
		Message msg = jxta.getMessage();		

		try{			
			el = msg.getMessageElement(MSG_ELEMENT_NAMESPACE, reqPipeTag);
			if (el != null) {				
				// if is JXTASOC and reqPipe, create a socketFlow
				@SuppressWarnings("rawtypes")
				XMLDocument adv = (XMLDocument) StructuredDocumentFactory.newStructuredDocument(el);
				PipeAdvertisement pipe = (PipeAdvertisement) AdvertisementFactory.newAdvertisement(adv);

				String strFlowId = new String(pipe.getPipeID().toString());
				Integer flowId = Integer.valueOf(strFlowId.hashCode());
				ArrayList<Jxta> flow = new ArrayList<Jxta>();
				flow.add(jxta);
				socketFlows.put(flowId, flow);
			}else{
				el = msg.getMessageElement(MSG_ELEMENT_NAMESPACE, remPipeTag);
				if(el != null){					
					// if is JXTASOC and remPipe, add to the socketFlow
					@SuppressWarnings("rawtypes")
					XMLDocument adv = (XMLDocument) StructuredDocumentFactory.newStructuredDocument(el);
					PipeAdvertisement pipe = (PipeAdvertisement) AdvertisementFactory.newAdvertisement(adv);

					String strFlowId = new String(pipe.getPipeID().toString());
					Integer flowId = Integer.valueOf(strFlowId.hashCode());
					ArrayList<Jxta> flow = new ArrayList<Jxta>();
					flow.add(jxta);
					socketFlows.put(flowId, flow);
				}else{	
					// if the EndpointRouterMsg destiny is for a socketFlow already saved, add to the socketFlow
					EndpointRouterMessage erm = new EndpointRouterMessage(msg,false);
					String strFlowId = erm.getDestAddress().getServiceParameter();
					Integer flowId = Integer.valueOf(strFlowId.hashCode());

					if(socketFlows.containsKey(flowId)){
						socketFlows.get(flowId).add(jxta);
					}else{
						ArrayList<Jxta> flow = new ArrayList<Jxta>();
						flow.add(jxta);
						socketFlows.put(flowId, flow);
					}
				}			
			}
		} catch (IOException e) {
			e.printStackTrace();            
		} catch (RuntimeException e) {
			e.printStackTrace();
		}
	}

	public static void flowPrettyPrint(ArrayList<Jxta> flow){
		for (Jxta jxta : flow) {
			JxtaMessageView.messagePrettyPrint(jxta);
		}
	}

	public static void flowStatistics(ArrayList<Jxta> flow){
		double tcpPay = 0;
		double jxtaPay = 0;
		double tmp = 0, t0 = Long.MAX_VALUE, t1 = Long.MIN_VALUE, time = 0;
		double v0 = 0;

		for (Jxta jxta : flow) {
			// Efficiency
			tcpPay += jxta.getJxtaPayload().length;
			jxtaPay += getMessageContent(jxta).length;

			// Throughput
			ArrayList<JPacket> pkts = jxta.getPackets();
			for (JPacket pkt : pkts) {
				tmp = pkt.getCaptureHeader().timestampInMillis();				
				if(tmp < t0)
					t0 = tmp;				
				if(tmp > t1)
					t1 = tmp;
			}
			
			//meantime
			if(v0 == 0){
				v0 = tmp;
			}else{
				System.out.println(tmp - v0);
				v0 = tmp;
			}
		}

		time = t1 - t0;
		if(time == 0)
			time = 1;

		try{
			System.out.println("### TCP Payload: " + (tcpPay)/1024 + " KB");
			System.out.println("### JXTA Payload: " + (jxtaPay)/1024 + " KB");
			System.out.println("### Transfer Time: " + time);
			System.out.println("### JXTA Throughput: " + (tcpPay/1024)/(time/1000) + " KB/s");
			System.out.println("### JXTA Overhead: " + ((tcpPay - jxtaPay)/(jxtaPay)) * 100 + " %");
		}catch(Exception e){

		}
	}
	
	public static void updateAfterDecode(JPacket packet, Jxta jxta){
		jxta.getPackets().add(packet);
		updateSocketFlows(jxta);
		int contentLength = getMessageContent(jxta).length;
		jxtaPayload += contentLength;
		tcpPayload += jxta.getJxtaPayload().length;
		//								if(contentLength > 0){
		//									flowPackets.addAll(jxta.getPackets());
		//								}
	}

}