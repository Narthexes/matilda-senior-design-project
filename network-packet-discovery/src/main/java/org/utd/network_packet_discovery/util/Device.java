package org.utd.network_packet_discovery.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class Device {

	public String ip = "";
	public String os = "";
	public String version = "";
	
	public List<String> vulnerabilities = new ArrayList<String>();
	
	public Device(String ipAddr) {
		ip = ipAddr;
	 	runNmap(ip);
	}
	
	public void runNmap(String ip) {
		String osVersion = "";
		String[] command = {"nmap", "-sV", "-O", " --script ",
				"smb-vuln-cve2009-3103,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067 ", ip};
		ProcessBuilder pb = new ProcessBuilder(command);
		pb.directory(new File(System.getProperty("user.home")));
		
		try {
			Process p = pb.start();
			BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
			
			String output;
			while((output = br.readLine()) != null) {
				if(os.equals("") && output.matches(".*Running.*")){
					String output2 = output;
			    	String output3 = output2.substring(output2.indexOf(":")+2);
			    	output3.trim();
			    	os = output3;
				}
				else if(version.equals("") && output.matches(".*OS details.*")) {
					String output2 = output;
					String output3 = output2.substring(output2.indexOf(":")+2);
					output3.trim();
					version = output3;
				}
				else if(output.matches(".*vulnerability.*")) {
		    	   vulnerabilities.add(output);
		       }
		       
			}
			
			int errorCode = p.waitFor();
			if(errorCode != 0) {
				System.out.println("\nError: " + errorCode);
			}
			
			
		} 
		catch(IOException e) {
			e.printStackTrace();
		}
		catch (InterruptedException e) {
			e.printStackTrace();
		}

	}
	
}
