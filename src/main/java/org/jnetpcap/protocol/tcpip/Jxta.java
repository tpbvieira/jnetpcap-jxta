package org.jnetpcap.protocol.tcpip;


import java.nio.ByteBuffer;

import net.jxta.endpoint.Message;
import net.jxta.impl.endpoint.msgframing.MessagePackageHeader;
import net.jxta.impl.endpoint.msgframing.WelcomeMessage;
import net.jxta.parser.JxtaParser;

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

	/** Constant numerical ID assigned to this protocol. */
	public static int ID;

	/** The message type. */
	private JxtaMessageType jxtaMessageType = null;

	/** Parsed welcome message. */
	private WelcomeMessage welcomeMsg = null;

	/** Parsed header. */
	private MessagePackageHeader headerMsg = null;

	/** Parsed msg. */
	private Message contentMsg = null;

	private byte[] rawWelcome = null;
	
	private byte[] rawHeader = null;
	
	private byte[] rawContent = null;
	
	static{
		try {  
			ID = JRegistry.register(Jxta.class);
		} catch (Exception e) {//TODO  
			e.printStackTrace();
		}  
	}

	private static boolean isWelcomeMessage(byte[] bufferArray){
		if(bufferArray == null || bufferArray.length < 9)
			return false;

		boolean ok = true;
		ok = ok && (bufferArray[0] == 74);
		ok = ok && (bufferArray[1] == 88);
		ok = ok && (bufferArray[2] == 84);
		ok = ok && (bufferArray[3] == 65);
		ok = ok && (bufferArray[4] == 72);
		ok = ok && (bufferArray[5] == 69);
		ok = ok && (bufferArray[6] == 76);
		ok = ok && (bufferArray[7] == 76);
		ok = ok && (bufferArray[8] == 79);

		return ok;
	}

	private static boolean isJxtaHeaderMessage(byte[] bufferArray){
		if(bufferArray == null || bufferArray.length < 9)
			return false;

		boolean ok = true;
		ok = ok && (bufferArray[0] == 12);
		ok = ok && (bufferArray[1] == 99);
		ok = ok && (bufferArray[2] == 111);
		ok = ok && (bufferArray[3] == 110);
		ok = ok && (bufferArray[4] == 116);
		ok = ok && (bufferArray[5] == 101);
		ok = ok && (bufferArray[6] == 110);
		ok = ok && (bufferArray[7] == 116);
		ok = ok && (bufferArray[8] == 45);
		ok = ok && (bufferArray[9] == 116);
		ok = ok && (bufferArray[10] == 121);
		ok = ok && (bufferArray[11] == 112);
		ok = ok && (bufferArray[12] == 101);
		ok = ok && (bufferArray[13] == 0);
		ok = ok && (bufferArray[14] == 22);
		ok = ok && (bufferArray[15] == 97);
		ok = ok && (bufferArray[16] == 112);
		ok = ok && (bufferArray[17] == 112);
		ok = ok && (bufferArray[18] == 108);
		ok = ok && (bufferArray[19] == 105);
		ok = ok && (bufferArray[20] == 99);
		ok = ok && (bufferArray[21] == 97);
		ok = ok && (bufferArray[22] == 116);
		ok = ok && (bufferArray[23] == 105);
		ok = ok && (bufferArray[24] == 111);
		ok = ok && (bufferArray[25] == 110);
		ok = ok && (bufferArray[26] == 47);
		ok = ok && (bufferArray[27] == 120);
		ok = ok && (bufferArray[28] == 45);
		ok = ok && (bufferArray[29] == 106);
		ok = ok && (bufferArray[30] == 120);
		ok = ok && (bufferArray[31] == 116);
		ok = ok && (bufferArray[32] == 97);

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
		byte[] bufferArray = null;

		if(buffer.size() > (68 + 9)){
			bufferArray = buffer.getByteArray(68, buffer.size() - 68);//clean message
			
			if(isWelcomeMessage(bufferArray)){
				length = bufferArray.length;
			}else				
				if(isJxtaHeaderMessage(bufferArray)){
					length = (buffer.findUTF8String(69, 'j','x','m','g') - 3);
				}
		}
		return length;
	}

	@Bind(to = Tcp.class)  
	public static boolean bindToTcp(JPacket packet, Tcp tpc) {
		return true;//TODO put effective verification 
	}  

	/**
	 * Decode first line.
	 * 
	 * @param buffer
	 */
	private void decodeFirstLine(byte[] buffer) {		
		if (isWelcomeMessage(buffer)) {
			setJxtaMessageType(JxtaMessageType.WELCOME);
		} else 
			if(isJxtaHeaderMessage(buffer)){
				setJxtaMessageType(JxtaMessageType.DEFAULT);
			}
	}

	/**
	 * Decode the jxta header.
	 */
	@Override
	protected void decodeHeader() {
		decodeFirstLine(this.getByteArray(0, this.size()));

		if(jxtaMessageType == JxtaMessageType.WELCOME){
			rawWelcome = this.getByteArray(0, this.size());
			welcomeMsg = JxtaParser.welcomeParser(ByteBuffer.wrap(rawWelcome));
		}else
			if(jxtaMessageType == JxtaMessageType.DEFAULT){
				rawHeader = this.getByteArray(0, this.size());
				headerMsg = JxtaParser.headerParser(ByteBuffer.wrap(rawHeader));
			}
	}

	public void decodeMessage(){
		if(jxtaMessageType == null)
			decodeHeader();

		if(jxtaMessageType == JxtaMessageType.DEFAULT){
			rawContent = this.getPayload();
			contentMsg = JxtaParser.processMessage(ByteBuffer.wrap(rawContent),headerMsg);
		}			
	}

	private void setJxtaMessageType(JxtaMessageType type) {
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

	public Message getContentMessage() {
		return contentMsg;
	}

	public byte[] getRawWelcome() {
		return rawWelcome;
	}

	public byte[] getRawHeader() {
		return rawHeader;
	}

	public byte[] getRawContent() {
		return rawContent;
	}

}