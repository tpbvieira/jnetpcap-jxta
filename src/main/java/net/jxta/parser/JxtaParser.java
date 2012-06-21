package net.jxta.parser;

import java.io.IOException;
import java.nio.ByteBuffer;

import net.jxta.document.MimeMediaType;
import net.jxta.endpoint.Message;
import net.jxta.endpoint.WireFormatMessageFactory;
import net.jxta.impl.endpoint.msgframing.MessagePackageHeader;
import net.jxta.impl.endpoint.msgframing.WelcomeMessage;
import net.jxta.parser.exceptions.JxtaBodyParserException;
import net.jxta.parser.exceptions.JxtaHeaderParserException;
import net.jxta.parser.exceptions.JxtaWelcomeParserException;

public class JxtaParser {

	public static WelcomeMessage welcomeParser(ByteBuffer buffer) throws IOException, JxtaWelcomeParserException{
		WelcomeMessage wecomeMsg = new WelcomeMessage();

		if(wecomeMsg.read(buffer))
			return wecomeMsg;
		else
			throw new JxtaWelcomeParserException("Error on welcome parser");

	}

	public static MessagePackageHeader headerParser(ByteBuffer buffer) throws IOException, JxtaHeaderParserException{
		MessagePackageHeader header = new MessagePackageHeader();
		if(header.readHeader(buffer))
			return header;
		else
			throw new JxtaHeaderParserException("Error on header parser");

	}

	public static Message processMessage(ByteBuffer buffer, MessagePackageHeader header) throws IOException, JxtaBodyParserException{
		MimeMediaType msgMime = header.getContentTypeHeader();
		Message msg = WireFormatMessageFactory.fromBuffer(buffer, msgMime, null);
		return msg;
	}
	
	public static Message messageParser(ByteBuffer buffer) throws IOException, JxtaHeaderParserException, JxtaBodyParserException{
		
		MessagePackageHeader header = new MessagePackageHeader();
		if(header.readHeader(buffer)){
			MimeMediaType msgMime = header.getContentTypeHeader();
			Message msg = WireFormatMessageFactory.fromBuffer(buffer, msgMime, null);
			return msg;
		}else
			throw new JxtaHeaderParserException("Error on header parser");		
	}
}