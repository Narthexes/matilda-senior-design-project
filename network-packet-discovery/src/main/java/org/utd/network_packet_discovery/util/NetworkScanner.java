package org.utd.network_packet_discovery.util;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Packet.IpV4Header;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper; 

public class NetworkScanner {

	private String networkInterface;
	private String targetSourceIp;
	private int maxPackets;
	
	private boolean breakFlag = false;
	
	private List<EasyPacket> packets = new ArrayList<EasyPacket>();
	
	private Set<String> relatedAddresses = new HashSet<String>();
	private List<Device> networkDevices = new ArrayList<Device>();
	
	private int totalPackets = 0;
	private int matchedPackets = 0;
	
	public NetworkScanner(String interf, String target, int max) {
		networkInterface = interf;
		targetSourceIp = target;
		maxPackets = max;
	}
	
	public static List<InetAddress> getInterfaces() {
		
		try {
			List<PcapNetworkInterface> devices;
			List<InetAddress> interfaces = new ArrayList<InetAddress>();
			
			devices = Pcaps.findAllDevs();
			
			for (PcapNetworkInterface device : devices) {
	    	    for(PcapAddress p : device.getAddresses()) {
	    	    	interfaces.add(p.getAddress());
	    	    }
	    	}
			
			return interfaces;
		} catch (PcapNativeException e) {
			e.printStackTrace();
			return null;
		}

	}
	
	public void scanNetwork() {
		breakFlag = false;
		try
        {
			InetAddress addr = InetAddress.getByName(networkInterface);
	    	PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);
	    	
	    	int snapLen = 65536;
	    	PromiscuousMode mode = PromiscuousMode.PROMISCUOUS;
	    	int timeout = 300;
	    	final PcapHandle handle;
	    	handle = nif.openLive(snapLen, mode, timeout);
	  
	    	// Create a listener that defines what to do with the received packets
	        PacketListener listener = new PacketListener() {
	            
	            public void gotPacket(PcapPacket packet) {
	            	totalPackets++;
	            	
	            	IpV4Header ipV4Header = packet.get(IpV4Packet.class).getHeader();
	            	Inet4Address srcAddr = ipV4Header.getSrcAddr();
	            	Inet4Address dstAddr = ipV4Header.getDstAddr();
	            	
	            	//Either specifically searches for a src address, or accepts all
	            	if(srcAddr.toString().equals("/" + targetSourceIp) ||
	            			dstAddr.toString().equals("/" + targetSourceIp) ||
	            			targetSourceIp.equals("")) {
	            		System.out.println("Found packets... for " + "/" + targetSourceIp);
	            		
	            		matchedPackets++;
	            		
	            		//Add any unknown src or dst addresses linked to the target IP to the address list
	            		String src = srcAddr.toString().replace("/", "");
	            		String dst = dstAddr.toString().replace("/", "");
	            		if(!relatedAddresses.contains(src)) { 
	            			relatedAddresses.add(src);
	            			networkDevices.add(new Device(src));
	            		}
	            		if(!relatedAddresses.contains(dst)) { 
	            			relatedAddresses.add(dst);	
	            			networkDevices.add(new Device(dst));
	            		}
	            		
	            		EasyPacket ep = new EasyPacket(packet);
	            		packets.add(ep);

	                    if(breakFlag || matchedPackets >= maxPackets) {
	                    	System.out.println("Breaking!");
							try {
								handle.breakLoop();
							} catch (NotOpenException e) {
								e.printStackTrace();
							}
	                    }
	            	}
	                
	            	if(totalPackets % 10 == 0) {
	            		System.out.println("Scanning packets...");
	            	}
	            }
	        };
	
	        // Tell the handle to loop using the listener we created
	        handle.loop(maxPackets, listener);
	
	        // Cleanup when complete
	        handle.close();
        }
        catch (InterruptedException e) 
        {
        	System.out.println ("Loop interrupted."); 
        }
        catch (Exception e) 
        { 
            System.out.println ("Exception is caught."); 
        } 
		
		for(String s : getRelatedAddresses())
			System.out.println(s);
		
		outputPacketsToJson();
		outputDevicesToJson();
	}
	
	public void outputPacketsToJson() {
		ObjectMapper mapper = new ObjectMapper();
		
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd ");  
		LocalDateTime now = LocalDateTime.now();  
		   
		try {
			System.out.println("Packets found: " + packets.size());
			PrintWriter out = new PrintWriter(dtf.format(now) + "packet_result.txt");
			
			// Java objects to JSON string - pretty-print
			String jsonInString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(packets);
			out.print(jsonInString);
			out.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		} 
	}
	
	public void outputDevicesToJson() {
		ObjectMapper mapper = new ObjectMapper();
		
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd ");  
		LocalDateTime now = LocalDateTime.now();  
		   
		try {
			System.out.println("Packets found: " + packets.size());
			PrintWriter out = new PrintWriter(dtf.format(now) + "device_result.txt");
			
			// Java objects to JSON string - pretty-print
			String jsonInString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(networkDevices);
			out.print(jsonInString);
			out.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		} 
	}
	
	public void stopNetworkScan() {
		breakFlag = true;
	}
	public Set<String> getRelatedAddresses(){
		return relatedAddresses;
	}
	
	public List<Device> getNetworkDevices(){
		return networkDevices;
	}
	

}
