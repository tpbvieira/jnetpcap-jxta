package net.jxta.parser;
import java.io.IOException;
import java.nio.ByteBuffer;

import net.jxta.document.MimeMediaType;
import net.jxta.endpoint.Message;
import net.jxta.endpoint.WireFormatMessageFactory;
import net.jxta.impl.endpoint.msgframing.MessagePackageHeader;
import net.jxta.impl.endpoint.msgframing.WelcomeMessage;

public class JxtaParser {

	public static WelcomeMessage welcomeParser(ByteBuffer buffer) {
		WelcomeMessage msg = new WelcomeMessage();
		try {
			if(msg.read(buffer))
				return msg;
			else
				throw new RuntimeException("Error on welcome parser");
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public static MessagePackageHeader headerParser(ByteBuffer buffer) {
		MessagePackageHeader header = new MessagePackageHeader();
		try{
			if(header.readHeader(buffer))
				return header;
			else
				throw new RuntimeException("Error on header parser");
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public static Message processMessage(ByteBuffer buffer, MessagePackageHeader header){
		MimeMediaType msgMime = header.getContentTypeHeader();
		Message msg = null;
		try {
			msg =  WireFormatMessageFactory.fromBuffer(buffer, msgMime, null);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return msg;
	}
}