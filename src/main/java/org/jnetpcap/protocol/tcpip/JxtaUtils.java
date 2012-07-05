package org.jnetpcap.protocol.tcpip;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;

import net.jxta.endpoint.Message;
import net.jxta.endpoint.MessageElement;
import net.jxta.impl.util.pipe.reliable.Defs;

import org.jnetpcap.protocol.network.Ip4;

import drivers.JxtaMessageViewDriver;


import sun.misc.IOUtils;

public class JxtaUtils {

	public static int getFlowId(Ip4 ip, Tcp tcp) {
		int[] id = new int[10];
		try{
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
		}catch(Exception e){
			e.printStackTrace();
		}
		return Arrays.hashCode(id);
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

	public static void flowPrettyPrint(ArrayList<Jxta> flow){
		for (Jxta jxta : flow) {
			JxtaMessageViewDriver.messagePrettyPrint(jxta);
		}
	}

}
