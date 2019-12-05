package org.utd.network_packet_discovery.util;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

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
	
	private List<PcapPacket> pcapPackets = new ArrayList<PcapPacket>();
	private List<EasyPacket> packets = new ArrayList<EasyPacket>();
	
	private Set<String> relatedAddresses = new HashSet<String>();
	private List<Device> networkDevices = new ArrayList<Device>();
	
	private int totalPackets = 0;
	private int matchedPackets = 0;
	
	public BlockingQueue<String> outputQueue = new ArrayBlockingQueue<String>(1024);
	
	public NetworkScanner(String interf, String target, int max) {
		networkInterface = interf;
		targetSourceIp = target;
		maxPackets = max;
		
		relatedAddresses.add(interf);
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
	            		
	            		//Add output to Queue
		            	outputQueue.add(srcAddr.toString() + " -> " + dstAddr.toString());
		            	pcapPackets.add(packet);
		            	matchedPackets++;
		            	
	            		//Add any unknown src or dst addresses linked to the target IP to the address list
	            		String src = srcAddr.toString().replace("/", "");
	            		String dst = dstAddr.toString().replace("/", "");
	            		if(!relatedAddresses.contains(src)) { 
	            			relatedAddresses.add(src);
	            			//networkDevices.add(new Device(src));
	            		}
	            		if(!relatedAddresses.contains(dst)) { 
	            			relatedAddresses.add(dst);	
	            			//networkDevices.add(new Device(dst));
	            		}
	            		
	            		
	            		
	                    if(breakFlag || matchedPackets >= maxPackets) {
	                    	outputQueue.add("Stopping Network Scan...");
							try {
								handle.breakLoop();
							} catch (NotOpenException e) {
								e.printStackTrace();
							}
	                    }
	                    
	                    
	            	}
	            	
	            	if(totalPackets % 30 == 0) {
                    	outputQueue.add("Scanning...(" + totalPackets + ")");
                    }
	                
	            }
	        };
	
	        // Tell the handle to loop using the listener we created
	        handle.loop(Integer.MAX_VALUE, listener);
	
	        // Cleanup when complete
	        handle.close();
        }
        catch (InterruptedException e) 
        {
        	
        }
        catch (Exception e) 
        { 
        	e.printStackTrace();
            System.out.println ("Exception is caught."); 
        }
		finally {
			
			outputQueue.add("Processing found packets...");
			for(PcapPacket packet : pcapPackets) {
				EasyPacket ep = new EasyPacket(packet);
        		packets.add(ep);
			}
			
			outputQueue.add("Starting OS Scan On Discovered Devices");
	        for(String s : relatedAddresses) {
	        	if(!s.equals(networkInterface)) {
	        		outputQueue.add("Querying Device: " + s);
	        		Device d = new Device(s);
	        		networkDevices.add(d);
	        		outputQueue.add("Vulnerabilities found: " + d.vulnerabilities.size());
	        	}
	        }
		        
	        outputQueue.add("Outputting Results...");
			outputPacketsToJson();
			outputDevicesToJson();
		}
		
		
	}
	
	public void outputPacketsToJson() {
		ObjectMapper mapper = new ObjectMapper();
		
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd ");  
		LocalDateTime now = LocalDateTime.now();  
		   
		try {
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
