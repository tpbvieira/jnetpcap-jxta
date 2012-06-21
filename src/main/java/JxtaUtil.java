import java.io.IOException;

import net.jxta.document.AdvertisementFactory;
import net.jxta.document.StructuredDocumentFactory;
import net.jxta.document.XMLDocument;
import net.jxta.endpoint.Message;
import net.jxta.endpoint.MessageElement;
import net.jxta.protocol.PeerAdvertisement;


public class JxtaUtil {
	
	public static PeerAdvertisement getConnectAdvertisement(Message msg){		
		MessageElement elem = msg.getMessageElement("jxta", "Connect");
		XMLDocument asDoc = null;
		try {
			asDoc = (XMLDocument) StructuredDocumentFactory.newStructuredDocument(elem);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return (PeerAdvertisement) AdvertisementFactory.newAdvertisement(asDoc);		
	}

}
