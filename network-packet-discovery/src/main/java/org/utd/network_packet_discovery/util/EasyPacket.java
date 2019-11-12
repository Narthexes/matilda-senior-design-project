package org.utd.network_packet_discovery.util;

import java.net.Inet4Address;
import java.time.Instant;

import org.pcap4j.core.PcapPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.util.ByteArrays;

public class EasyPacket{
	
	String timestamp;
	
	String mac;
	String net_card;
	
	String src_addr_hostaddress;
	String dst_addr_hostaddress;
	String src_addr_hostname;
	String dst_addr_hostname;
	
	String raw_byte_payload;
	String hex_data_payload;
	String char_data_payload;
	
	public EasyPacket(PcapPacket p) {
		timestamp = p.getTimestamp().toString();
		
		IpV4Packet ipV4Packet = p.get(IpV4Packet.class);
		Inet4Address srcAddr = ipV4Packet.getHeader().getSrcAddr();
    	Inet4Address dstAddr  = ipV4Packet.getHeader().getDstAddr();
    	
    	src_addr_hostaddress = srcAddr.getHostAddress();
    	src_addr_hostname = srcAddr.getCanonicalHostName();
    	
    	dst_addr_hostaddress = dstAddr.getHostAddress();
    	dst_addr_hostname = dstAddr.getCanonicalHostName();
    	
    	if(p.getRawData() != null) {
    		raw_byte_payload = p.getRawData().toString();
    		hex_data_payload = p.get(UnknownPacket.class).toHexString();
    		char_data_payload = hexStringToCharString(hex_data_payload);
    	}
	}
	
	private String hexStringToCharString(String hex) {
		StringBuilder builder = new StringBuilder();
		
		for(String s : hex.split(" ")) {
			int res = Integer.valueOf(s, 16);
			builder.append((char)res);
		}

		System.out.println(builder.toString());
		return builder.toString();
	}
}
