package org.utd.network_packet_discovery.util;

import java.io.Serializable;
import java.net.Inet4Address;

import org.pcap4j.core.PcapPacket;
import org.pcap4j.packet.AbstractPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.EthernetPacket.EthernetHeader;
import org.pcap4j.packet.FragmentedPacket;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TcpPacket.TcpHeader;
import org.pcap4j.packet.UnknownPacket;

public class EasyPacket implements Serializable{

	public String timestamp = "";
	
	public String mac_src_addr = "";
	public String mac_dst_addr = "";
	public String ethernet_type = "";
	
	public String tcp_src_port = "";
	public String tcp_dst_port = "";
	
	public String ipv4_src_addr_hostaddress = "";
	public String ipv4_dst_addr_hostaddress = "";
	public String ipv4_src_addr_hostname = "";
	public String ipv4_dst_addr_hostname = "";
	
	public String char_data_payload = "";
	
	public EasyPacket(PcapPacket p) {
		//System.out.println(p);
		timestamp = p.getTimestamp().toString();
		
		//Ethernet Header
		EthernetHeader ethernetHeader = p.get(EthernetPacket.class).getHeader();
		mac_dst_addr = ethernetHeader.getDstAddr().toString();
		mac_src_addr = ethernetHeader.getSrcAddr().toString();
		
		
		//IpV4 Header
		IpV4Packet ipV4Packet = p.get(IpV4Packet.class);
		Inet4Address srcAddr = ipV4Packet.getHeader().getSrcAddr();
    	Inet4Address dstAddr  = ipV4Packet.getHeader().getDstAddr();
    	
    	ipv4_src_addr_hostaddress = srcAddr.getHostAddress();
    	ipv4_src_addr_hostname = srcAddr.getCanonicalHostName();
    	
    	ipv4_dst_addr_hostaddress = dstAddr.getHostAddress();
    	ipv4_dst_addr_hostname = dstAddr.getCanonicalHostName();
    	
    	//TCP Header 
    	TcpHeader tcpHeader = p.get(TcpPacket.class).getHeader();
    	tcp_src_port = tcpHeader.getSrcPort().toString();
    	tcp_dst_port = tcpHeader.getDstPort().toString();
    	

    	//Any Hex Data
    	if(p.getRawData() != null) {
    		//System.out.println("Getting Hex Data");
    		if(p.get(UnknownPacket.class) != null) {
    			String hex_data_payload = p.get(UnknownPacket.class).toHexString();
        		char_data_payload = hexStringToCharString(hex_data_payload);
    		}
    		else if(p.get(AbstractPacket.class) != null) {
    			char_data_payload = p.get(AbstractPacket.class).toHexString();
    		}
    	}
    	
	}
	
	private String hexStringToCharString(String hex) {
		StringBuilder builder = new StringBuilder();
		
		for(String s : hex.split(" ")) {
			int res = Integer.valueOf(s, 16);
			builder.append((char)res);
		}

		return builder.toString();
	}
	
}
