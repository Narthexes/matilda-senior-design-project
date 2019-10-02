package org.utd.network_packet_discovery;

import java.io.EOFException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.TimeoutException;
import java.util.*;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

public class Main 
{
    public static void main( String[] args ) throws UnknownHostException, PcapNativeException, EOFException, TimeoutException, NotOpenException
    {
    	System.out.println("#### LIST OF DEVS ####");

    	List<PcapNetworkInterface> devices = Pcaps.findAllDevs();

    	for (PcapNetworkInterface device : devices) {
    	    for(PcapAddress p : device.getAddresses()) {
    	    	System.out.println(p.getAddress().getHostAddress());
    	    }
    	}
    	System.out.println("###############");
    	
    	
    	//InetAddress addr = InetAddress.getByName("10.176.138.16");
    	InetAddress addr = InetAddress.getByName("10.176.138.22");
    	PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);
    	
    	int snapLen = 65536;
    	PromiscuousMode mode = PromiscuousMode.PROMISCUOUS;
    	int timeout = 20;
    	PcapHandle handle = nif.openLive(snapLen, mode, timeout);
    	
    	//Get Packet
    	Packet packet = null;
    	
    	while(packet == null) {
    		try {
    		packet = handle.getNextPacketEx();
    		}
    		catch(TimeoutException ex) {
    			System.out.println("Timed out!");
    		}
    	}
    	handle.close();
    	
    	//Get packet info
    	IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
    	Inet4Address srcAddr = ipV4Packet.getHeader().getSrcAddr();
    	System.out.println(srcAddr);
    	for(byte i: ipV4Packet.getRawData()) {
    		System.out.print(i);
    	}
    	
    }
}
