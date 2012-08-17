package org.jnetpcap.protocol.tcpip;

import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.SortedMap;
import java.util.TreeMap;

import net.jxta.endpoint.Message;
import net.jxta.impl.endpoint.msgframing.MessagePackageHeader;
import net.jxta.impl.endpoint.msgframing.WelcomeMessage;
import net.jxta.parser.JxtaParser;
import net.jxta.parser.exceptions.JxtaBodyParserException;
import net.jxta.parser.exceptions.JxtaHeaderParserException;
import net.jxta.parser.exceptions.JxtaWelcomeParserException;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.packet.annotate.HeaderLength;
import org.jnetpcap.packet.annotate.ProtocolSuite;


/**
 * The Class AbstractMessageHeader.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
@Header( suite = ProtocolSuite.TCP_IP)
public class Jxta extends JHeader {

	/**
	 * The Enum JxtaMessageType.
	 */
	public enum JxtaMessageType {
		WELCOME,
		DEFAULT
	}

	public enum JxtaState {
		UNKNOWN,
		WELCOME,
		HEADER,
		MESSAGE
	}

	public static int ID;

	private JxtaMessageType jxtaMessageType;

	private WelcomeMessage welcomeMsg;

	private MessagePackageHeader headerMsg;

	private byte[] rawHeader;

	private Message message;

	private byte[] jxtaPayload;

	private byte[] remain;

	private boolean isFragmented;

	private JxtaState jxtaState;

	private SortedMap<Long,JPacket> packets;

	static{
		try {  
			ID = JRegistry.register(Jxta.class);
		} catch (Exception e) {//TODO  
			e.printStackTrace();
		}
	}

	public static boolean isWelcomeMessage(byte[] bufferArray){
		if(bufferArray == null || bufferArray.length < 9)
			return false;

		boolean ok = true;
		ok = ok && (bufferArray[0] == 74);// J
		ok = ok && (bufferArray[1] == 88);// X
		ok = ok && (bufferArray[2] == 84);// T
		ok = ok && (bufferArray[3] == 65);// A
		ok = ok && (bufferArray[4] == 72);// H
		ok = ok && (bufferArray[5] == 69);// E
		ok = ok && (bufferArray[6] == 76);// L
		ok = ok && (bufferArray[7] == 76);// L
		ok = ok && (bufferArray[8] == 79);// O

		return ok;
	}

	public static boolean isJxtaHeaderMessage(byte[] bufferArray){
		if(bufferArray == null || bufferArray.length < 15)
			return false;

		boolean ok = true;
		//		ok = ok && (bufferArray[0] == 12);//	?
		ok = ok && (bufferArray[1] == 99);//	c
		ok = ok && (bufferArray[2] == 111);//	o
		ok = ok && (bufferArray[3] == 110);//	n
		ok = ok && (bufferArray[4] == 116);//	t
		ok = ok && (bufferArray[5] == 101);//	e
		ok = ok && (bufferArray[6] == 110);//	n
		ok = ok && (bufferArray[7] == 116);//	t
		ok = ok && (bufferArray[8] == 45);//	-
		ok = ok && (bufferArray[9] == 108);//	l	
		ok = ok && (bufferArray[10] == 101);//	e
		ok = ok && (bufferArray[11] == 110);//	n
		ok = ok && (bufferArray[12] == 103);//	g
		ok = ok && (bufferArray[13] == 116);//	t
		ok = ok && (bufferArray[14] == 104);//	h

		//		 UDP header??
		//		if(!ok){
		//			ok = true;
		//			ok = ok && (bufferArray[0] == 74);// J
		//			ok = ok && (bufferArray[1] == 88);// X
		//			ok = ok && (bufferArray[2] == 84);// T
		//			ok = ok && (bufferArray[3] == 65);// A
		//			ok = ok && (bufferArray[5] == 99);//	c
		//			ok = ok && (bufferArray[6] == 111);//	o
		//			ok = ok && (bufferArray[7] == 110);//	n
		//			ok = ok && (bufferArray[8] == 116);//	t
		//			ok = ok && (bufferArray[9] == 101);//	e
		//			ok = ok && (bufferArray[10] == 110);//	n
		//			ok = ok && (bufferArray[11] == 116);//	t
		//		}

		return ok;
	}

	/**
	 * ...
	 * 
	 * @param buffer
	 * @param offset
	 */
	@HeaderLength 
	public static int headerLength(JBuffer buffer, int offset) {
		int length = 0;
		byte[] bytes = null;

		if(buffer.size() > (offset + 9)){
			bytes = buffer.getByteArray(offset, buffer.size() - offset);//jxta message array			
			if(isWelcomeMessage(bytes)){
				length = bytes.length;
			}else				
				if(isJxtaHeaderMessage(bytes)){
					length = (buffer.findUTF8String(offset, 'j','x','m','g') - 4);
				}
		}
		return length;
	}

	@Bind(to = Tcp.class)  
	public static boolean bindToTcp(JPacket packet, Tcp tpc) {
		return true;//TODO put effective verification 
	}

	@Bind(to = Udp.class)  
	public static boolean bindToUdp(JPacket packet, Udp udp) {
		return true;//TODO put effective verification 
	}


	public Jxta(){		
		rawHeader = new byte[0];
		jxtaPayload = new byte[0];
		remain = new byte[0];
		isFragmented = false;
		packets = new TreeMap<Long,JPacket>();	
	}


	/**
	 * verify and set the message type, using information from first line of bytes.
	 * 
	 * @param bytes
	 */
	private void setMessageType(byte[] bytes) {		
		if (isWelcomeMessage(bytes)) {
			setJxtaMessageType(JxtaMessageType.WELCOME);
			setJxtaState(JxtaState.WELCOME);
		} else 
			if(isJxtaHeaderMessage(bytes)){
				setJxtaMessageType(JxtaMessageType.DEFAULT);
				setJxtaState(JxtaState.HEADER);
			}
	}

	/**
	 * Decode the JXTA header.
	 * For cases where does not exists fragmentation
	 */
	@Override
	protected void decodeHeader() {
		jxtaState = JxtaState.UNKNOWN;
		setMessageType(this.getByteArray(0, this.size()));		

		try{
			if(jxtaMessageType == JxtaMessageType.WELCOME){
				jxtaState = JxtaState.WELCOME;
				ByteBuffer buffer = ByteBuffer.wrap(this.getByteArray(0, this.size()));
				int t0 = buffer.position();
				welcomeMsg = JxtaParser.welcomeParser(buffer);
				rawHeader = this.getByteArray(0, buffer.position() - t0);
				jxtaPayload = rawHeader;
				jxtaState = JxtaState.UNKNOWN;
			}else
				if(jxtaMessageType == JxtaMessageType.DEFAULT){
					jxtaState = JxtaState.HEADER;
					ByteBuffer buffer = ByteBuffer.wrap(this.getByteArray(0, this.size()));
					int t0 = buffer.position();
					headerMsg = JxtaParser.headerParser(buffer);
					rawHeader = this.getByteArray(0, buffer.position() - t0);
					jxtaPayload = rawHeader;					
					jxtaState = JxtaState.MESSAGE;
				}
		}catch(JxtaWelcomeParserException e){
			throw new RuntimeException("Error decondig jxta welcome message", new JxtaWelcomeParserException(e));
		}catch(JxtaHeaderParserException e){
			throw new RuntimeException("Error decondig jxta header message", new JxtaHeaderParserException(e));
		}catch(IOException e){
			throw new RuntimeException("RuntimeError decondig jxta header message", new JxtaHeaderParserException(e));
		}
	}

	// for cases where does not exists fragmentation
	public void decodeMessage() throws IOException{
		if(jxtaMessageType == null)
			decodeHeader();

		jxtaState = JxtaState.MESSAGE;

		if(jxtaMessageType == JxtaMessageType.DEFAULT){
			ByteBuffer buffer = ByteBuffer.wrap(this.getPayload());

			// save payload before to process the message
			jxtaPayload = new byte[rawHeader.length + buffer.remaining()];
			System.arraycopy(rawHeader, 0, jxtaPayload, 0, rawHeader.length);
			System.arraycopy(buffer.array(), buffer.position(), jxtaPayload, rawHeader.length, buffer.remaining());

			int t0 = buffer.position();
			try {
				message = JxtaParser.processMessage(buffer,headerMsg);
			} catch (JxtaBodyParserException e) {
				throw new RuntimeException("Error decondig jxta body message", new JxtaBodyParserException(e));
			}
			int msgLen = buffer.position() - t0;

			jxtaPayload = new byte[rawHeader.length + msgLen];

			System.arraycopy(rawHeader, 0, jxtaPayload, 0, rawHeader.length);//copy header into new payload
			System.arraycopy(buffer.array(), buffer.position() - msgLen, jxtaPayload, rawHeader.length, msgLen);//copy massage into new payload

			isFragmented = (buffer.remaining() > 0);
			if(isFragmented){
				jxtaState = JxtaState.HEADER;				
				remain = new byte[buffer.remaining()];
				System.arraycopy(buffer.array(), buffer.position(), remain, 0, remain.length);
			}else{
				jxtaState = JxtaState.UNKNOWN;
			}
		}else{
			throw new RuntimeException("Incompatible message type");
		}
	}

	public void decode(long seqNumber, JPacket packet, ByteBuffer buffer) throws IOException, JxtaHeaderParserException{		
		decode(buffer);
		packets.put(seqNumber, packet);
	}

	public void decode(ByteBuffer buffer) throws IOException, JxtaHeaderParserException{
		setMessageType(buffer.array());

		if(jxtaMessageType == JxtaMessageType.WELCOME){			
			decodeWelcome(buffer);
		}else
			if(jxtaMessageType == JxtaMessageType.DEFAULT){
				if(getJxtaState() == JxtaState.HEADER)
					decodeHeader(buffer);
				else
					buffer.position(rawHeader.length);// puts the buffer position after the header
				decodeMessage(buffer);
			}else
				if(jxtaMessageType == null && buffer.array().length < 9){
					jxtaMessageType = JxtaMessageType.DEFAULT;
					jxtaState = JxtaState.HEADER;
					decodeHeader(buffer);
				}

	}

	private void decodeWelcome(ByteBuffer buffer) throws IOException{
		welcomeMsg = null;		
		jxtaState = JxtaState.WELCOME;

		// save before
		jxtaPayload = new byte[buffer.remaining()];
		System.arraycopy(buffer.array(), buffer.position(), jxtaPayload, 0, buffer.remaining());		

		int t0 = buffer.position();
		try {
			welcomeMsg = JxtaParser.welcomeParser(buffer);
		} catch (JxtaWelcomeParserException e) {
			throw new RuntimeException("Error decondig jxta welcome message", new JxtaWelcomeParserException(e));
		}
		jxtaPayload = new byte[buffer.position() - t0];

		System.arraycopy(buffer.array(), buffer.position(), jxtaPayload, 0, jxtaPayload.length);
		rawHeader = jxtaPayload;
		jxtaState = JxtaState.UNKNOWN;
	}

	public void decodeHeader(ByteBuffer buffer) throws IOException,JxtaHeaderParserException{
		// Header
		headerMsg = null;
		jxtaState = JxtaState.HEADER;		

		// save before
		jxtaPayload = new byte[buffer.remaining()];
		System.arraycopy(buffer.array(), buffer.position(), jxtaPayload, 0, buffer.remaining());

		int t0 = buffer.position();

		headerMsg = JxtaParser.headerParser(buffer);
		rawHeader = new byte[buffer.position() - t0];

		System.arraycopy(buffer.array(), buffer.position() - rawHeader.length, rawHeader, 0,rawHeader.length);		
		jxtaPayload = rawHeader;
		jxtaState = JxtaState.MESSAGE;
	}

	public void decodeMessage(ByteBuffer buffer) throws IOException{
		// Message		
		jxtaState = JxtaState.MESSAGE;

		jxtaPayload = new byte[rawHeader.length + buffer.remaining()];// resizes payload
		System.arraycopy(rawHeader, 0, jxtaPayload, 0, rawHeader.length);//copy header into payload
		System.arraycopy(buffer.array(), buffer.position(), jxtaPayload, rawHeader.length, buffer.remaining());//copy massage into payload

		int p0 = buffer.position();				
		try {
			message = JxtaParser.processMessage(buffer,headerMsg);
		} catch (JxtaBodyParserException e) {
			throw new RuntimeException("Error decondig jxta body message", new JxtaBodyParserException(e));
		}
		int msgLen = buffer.position() - p0;

		jxtaPayload = new byte[rawHeader.length + msgLen];// resizes payload
		System.arraycopy(rawHeader, 0, jxtaPayload, 0, rawHeader.length);//copy header into payload
		System.arraycopy(buffer.array(), buffer.position() - msgLen, jxtaPayload, rawHeader.length, msgLen);//copy massage into payload

		isFragmented = (buffer.remaining() > 0);
		if(isFragmented){
			jxtaState = JxtaState.HEADER;			
			remain = new byte[buffer.remaining()];
			System.arraycopy(buffer.array(), buffer.position(), remain, 0, remain.length);
		}else{
			jxtaState = JxtaState.UNKNOWN;
		}
	}

	public void setJxtaMessageType(JxtaMessageType type) {
		this.jxtaMessageType = type;
	}

	public JxtaMessageType getJxtaMessageType() {
		return this.jxtaMessageType;
	}

	public WelcomeMessage getWelcomeMessage() {
		return welcomeMsg;
	}

	public MessagePackageHeader getHeaderMessage() {
		return headerMsg;
	}

	public Message getMessage() {
		return message;
	}

	public void setMessage(Message msg) {
		message = msg;
	}

	public boolean isFragmented() {
		return isFragmented;
	}

	public void setFragmented(boolean isFragmented) {
		this.isFragmented = isFragmented;
	}

	public JxtaState getJxtaState() {
		return jxtaState;
	}

	public void setJxtaState(JxtaState jxtaState) {
		this.jxtaState = jxtaState;
	}

	public byte[] getRemain() {
		return remain;
	}

	public void setRemain(byte[] remain) {
		this.remain = remain;
	}

	public WelcomeMessage getWelcomeMsg() {
		return welcomeMsg;
	}

	public void setWelcomeMsg(WelcomeMessage welcomeMsg) {
		this.welcomeMsg = welcomeMsg;
	}

	public MessagePackageHeader getHeaderMsg() {
		return headerMsg;
	}

	public void setHeaderMsg(MessagePackageHeader headerMsg) {
		this.headerMsg = headerMsg;
	}

	public byte[] getJxtaPayload() {
		return jxtaPayload;
	}

	public void setJxtaPayload(byte[] payload) throws BufferUnderflowException, IOException, JxtaHeaderParserException {
		this.jxtaPayload = payload;
		ByteBuffer buffer = ByteBuffer.wrap(payload);
		decodeHeader(buffer);
		decodeMessage(buffer);
	}

	public SortedMap<Long,JPacket> getJxtaPackets() {
		return packets;
	}
}