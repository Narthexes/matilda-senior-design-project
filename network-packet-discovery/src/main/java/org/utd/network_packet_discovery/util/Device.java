package org.utd.network_packet_discovery.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class Device {

	public String ip;
	public String os;
	public List<String> vulnerabilities;
	
	public Device(String ipAddr) {
		ip = ipAddr;
	 	os = pollForOS(ip);
	 	vulnerabilities = findVulnerabilties(os);
	}
	
	public String pollForOS(String ip) {
		String osVersion = "";
		
		String[] command = {"nmap", "-sV", "-O", ip};
		ProcessBuilder pb = new ProcessBuilder(command);
		pb.directory(new File(System.getProperty("user.home")));
		
		try {
			Process p = pb.start();
			BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
			
			String output;
			int i=0;
			while((output = br.readLine()) != null) {
		       if(i==18 || i == 20) {
		        	System.out.println(output);
		        	osVersion = "";
		        }
		        i++;
			}
			
			int errorCode = p.waitFor();
			System.out.println("\nError: " + errorCode);
			
		} 
		catch(IOException e) {
			e.printStackTrace();
		}
		catch (InterruptedException e) {
			e.printStackTrace();
		}
		
		return osVersion;
	}
	
	public List<String> findVulnerabilties(String os) {
		List<String> vulnerabilities = new ArrayList<String>();
		
		//Code here//
		
		return vulnerabilities;
	}
}
