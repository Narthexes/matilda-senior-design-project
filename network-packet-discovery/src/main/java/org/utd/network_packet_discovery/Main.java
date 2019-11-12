package org.utd.network_packet_discovery;

import java.io.EOFException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.TimeoutException;
import java.util.*;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.NifSelector;
import org.utd.network_packet_discovery.util.EasyPacket;

import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

class NetworkListener extends Thread{
	String ip;
	int id;
	int counter = 0;
	ObjectMapper mapper = new ObjectMapper();
	List<EasyPacket> packets = new ArrayList<EasyPacket>();
	File file = new File("result.txt");
	PrintWriter out;
	
	public NetworkListener(String targetIP, int id) {
		ip = targetIP;
		this.id = id;
	}
	
	public void run() 
    { 
        try
        { 
        	mapper.setVisibility(PropertyAccessor.FIELD, Visibility.ANY);
        	
        	
        	InetAddress addr = InetAddress.getByName(ip);
        	PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);
        	
        	int snapLen = 65536;
        	PromiscuousMode mode = PromiscuousMode.PROMISCUOUS;
        	int timeout = 300;
        	final PcapHandle handle;
        	handle = nif.openLive(snapLen, mode, timeout);
      
        	// Create a listener that defines what to do with the received packets
            PacketListener listener = new PacketListener() {
                
                public void gotPacket(PcapPacket packet) {
                    // Override the default gotPacket() function and process packet
                	IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);

                	Inet4Address srcAddr = ipV4Packet.getHeader().getSrcAddr();
                	Inet4Address dstAddr  = ipV4Packet.getHeader().getDstAddr();
                	//System.out.println(id + ": " + srcAddr.getCanonicalHostName() + " -> " + dstAddr.getHostAddress());
                	
                	//||dstAddr.toString().equals("/10.176.138.16")
                	if(srcAddr.toString().equals("/10.176.138.16")) {
//                		System.out.println(ByteArrays.toHexString(packet.getRawData(), " "));
//                		System.out.println(packet.getRawData().length);
//                		System.out.println("========");
                		System.out.println(packet.getPacket());

//                      packets.add(packet);
                		
                		EasyPacket ep = new EasyPacket(packet);
                		packets.add(ep);
                        if(counter++ > 1) {
                        	System.out.println("Breaking!");
							try {
								handle.breakLoop();
							} catch (NotOpenException e) {
								e.printStackTrace();
							}
                        }
                	}
                    
                }
            };

            // Tell the handle to loop using the listener we created

            int maxPackets = 3000;
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
            // Throwing an exception 
            System.out.println ("Exception is caught."); 
        } 
        finally {
        		
    		try {
    			PrintWriter out = new PrintWriter("result.txt"); 
    			// Java objects to JSON string - pretty-print
				String jsonInString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(packets);
				//System.out.println(jsonInString);
				//out.print(jsonInString);
			} catch (JsonProcessingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

        }
        
    } 
}

public class Main 
{
	//Requires WinPCap installation to run
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
    	
    	//Target
    	//InetAddress addr = InetAddress.getByName("10.176.138.16");
        
    	int n = 1; // Number of threads 
        for (int i=0; i<n; i++) 
        { 
        	//System.out.println("Thread " + i);
        	//"10.176.138.22"
        	NetworkListener object = new NetworkListener("10.176.138.22", i); 
            object.start(); 
        } 
    	
    }
    
}
