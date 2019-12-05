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
	public String version;
	
	public List<String> vulnerabilities;
	
	public Device(String ipAddr) {
		ip = ipAddr;
	 	os = pollForOS(ip);
	 	vulnerabilities = findVulnerabilties(os);
	}
	
	public String pollForOS(String ip) {
		String osVersion = "";
		String[] command = {"nmap", "-sV", "-O", " --script " +
				"http-vuln-cve2011-3192,http-vuln-cve2011-3368,http-vuln-cve2015-1635,http-vuln-cve2017-5638", ip};
		//"--script" "http-vuln-cve2011-3192""http-vuln-cve2011-3368,""http-vuln-cve2015-1635,""http-vuln-cve2017-5638"
		ProcessBuilder pb = new ProcessBuilder(command);
		pb.directory(new File(System.getProperty("user.home")));
		
		try {
			Process p = pb.start();
			BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
			
			String output;
			int i=0;
			while((output = br.readLine()) != null) {
		       if(i == 19) {
		    	   String output2 = output;
		    	   String output3 = output2.substring(output2.indexOf(":")+2);
		    	   output3.trim();
		    	   os = output3;
		       }
		       else if(i == 21) {
		    	   String output2 = output;
		    	   String output3 = output2.substring(output2.indexOf(":")+2);
		    	   output3.trim();
		    	   version = output3;
		    	   break;
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
