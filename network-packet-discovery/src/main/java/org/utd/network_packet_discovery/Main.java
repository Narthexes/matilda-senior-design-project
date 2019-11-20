package org.utd.network_packet_discovery;

import java.io.EOFException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.TimeoutException;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.utd.network_packet_discovery.util.NetworkScanner;

public class Main 
{
	//Requires WinPCap installation to run
    public static void main( String[] args ) throws UnknownHostException, PcapNativeException, EOFException, TimeoutException, NotOpenException
    {
    	for(InetAddress inter : NetworkScanner.getInterfaces()) {
    		System.out.println(inter.getHostName() + ", " + inter.getHostAddress());
    	}
    	
    	//Accepts the interface selected (IP format), the IP it wishes to read from, and the max packets to scan
    	NetworkScanner scanner = new NetworkScanner("10.176.138.22", "10.176.138.16", 10);
    	
    	scanner.scanNetwork();
    	
    	scanner.outputToJson();
    }
    
}
