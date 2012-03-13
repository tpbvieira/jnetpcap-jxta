package net.jxta.parser;

import java.io.IOException;
import java.nio.ByteBuffer;

import net.jxta.document.MimeMediaType;
import net.jxta.endpoint.Message;
import net.jxta.endpoint.WireFormatMessageFactory;
import net.jxta.impl.endpoint.msgframing.MessagePackageHeader;
import net.jxta.impl.endpoint.msgframing.WelcomeMessage;

public class JxtaParser {

	public static WelcomeMessage welcomeParser(ByteBuffer buffer) throws IOException{
		WelcomeMessage msg = new WelcomeMessage();

		if(msg.read(buffer))
			return msg;
		else
			throw new RuntimeException("Error on welcome parser");

	}

	public static MessagePackageHeader headerParser(ByteBuffer buffer) throws IOException{
		MessagePackageHeader header = new MessagePackageHeader();
		if(header.readHeader(buffer))
			return header;
		else
			throw new RuntimeException("Error on header parser");

	}

	public static Message processMessage(ByteBuffer buffer, MessagePackageHeader header) throws IOException{
		MimeMediaType msgMime = header.getContentTypeHeader();
		Message msg = null;

		msg =  WireFormatMessageFactory.fromBuffer(buffer, msgMime, null);

		return msg;
	}
}