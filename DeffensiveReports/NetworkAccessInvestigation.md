# Network Access Investigation - PCAP Packet Analysis
<b>INCIDENT REPORT: JA-16645-EriksCoffee </b>

## Executive Summary 
Erik’s Coffee Shop has two access points onto its network. One has been compromised with malware. This investigation is to determine which host computer was infected and the details of that intrusion. 

User details and access points to investigate: 

<u>User 1: </u>

IP address: 10.0.0.167

MAC address: HewlettP_f5:37:e5 (ac:16:2d:f5:37:e5)

Host name: DESKTOP-GRIONXA.steelcoffee.net 

User account name: elmer.obrien

<u>User 2:</u>

IP address: 10.0.0.149

MAC address: HewlettP_f7:80:b6 (6c:c2:17:f7:80:b6) 

Host name: DESKTOP-C10SKPY.steelcoffee.net

User account name: alyssa.fitzgerald

## Methodology 
- WireShark Version 4.0.3    
    Running on Linux 6.1.0-kali5-amd64, with 12th Gen Intel(R) Core(TM) i7-12700H
    - Filter: kerberos.CNameString    
    To identify the usernames: >Kerberos > as-req > req-body > cname > cname-string
    - Filter: frame contains "This program cannot be run in DOS mode.   
    “This program cannot be run in DOS mode.” is a red flag when the content type is image/png. 
    ![DOS red flag](https://github.com/serengetijade/Cyber_Security/blob/main/img/NetworkAccess-DOS.jpg)
    - Filter: http contains “8888.png”        
        - Follow > TCP stream        
        Follow the TCP streams to search for suspicious code. 
    - Export Objects to download the largest “8888.png” result        
        ![Export HTTP Objects](https://github.com/serengetijade/Cyber_Security/blob/main/img/NetworkAccess-ExportObjects.jpg)
    - Filter: ip.addr == 104.24.111.29 and http contains “GET”
- VirusTotal.com  - an online scanner that analyzes files and URLs for viruses, worms, trojans and other kinds of malicious content.     
    ![VirusTotal scan results](https://github.com/serengetijade/Cyber_Security/blob/main/img/NetworkAccess-VirusTotal.jpg)
    - Relations tab: The nearest relation file provieds more information about this malware: such as the Process Tree, and the .exe file.    
    ![VirusTotal process tree](https://github.com/serengetijade/Cyber_Security/blob/main/img/NetworkAccess-ProcessTree.jpg)

## Findings/Results 
Malware Type: Trojan Downloader

Name:  HEUR_JSRANSOM.O6

Host: afsholdings.com.my

User Agent: LaraConf

ProcessID: 3EB3C877-1F16-487C-9050-104DBCD66683

Malware Packet: 5520 - contains “This cannot be run in DOS mode.” but is type image. 

### Attack Narrative
On Thursday, April 23, 2020 at 23:18:32 UTC, user elmer.obrien on DESKTOP-GRIONXA.steelcoffee.net, accessed atn24live.com. The 
file 8888.png contained php instructions for malware. 

### Victim details
<u>User 1:</u>

IP address: 10.0.0.167

MAC address: HewlettP_f5:37:e5 (ac:16:2d:f5:37:e5)

Host name: DESKTOP-GRIONXA.steelcoffee.net 

User account name: elmer.obrien

### Indicators of compromise (IOCs) 
Users reported strange behavior. 

### Malicious HTTP traffic 
Wireshark filter: http contains “8888.png”

![Malicious 8888.png files](https://github.com/serengetijade/Cyber_Security/blob/main/img/NetworkAccess-8888.jpg)

### Suspicious domains using HTTPS traffic 
atn24live.com
* Hostname: atn24live.com
* IP address: 104.24.111.29
* MAC address: Netgear_b6:93:f1 (20:e5:2a:b6:93:f1)

asfholdings.com.my
* Hostname: bg142.caliphs.my
* IP address: 220.158.200.181
* MAC address: Netgear_b6:93:f1 (20:e5:2a:b6:93:f1)

alphapioneer.com
* Hostname: alphapioneer.com
* IP address: 119.31.234.40
* MAC address: Netgear_b6:93:f1 (20:e5:2a:b6:93:f1)

Note: several domains have the same MAC address, but different IPs. This can happen when multiple devices use the same network interface. 

## Conclusion 
Steganography, or simply stego, is a technique to hide harmful code within innocuous file types, such as image files. The malware code may be attached to the end of a file, hide within individual bits of the file’s code, or sit inside the metadata of the file. And it may trigger various types of malware. 

To protect against this threat, it is important to keep applications updated- especially browsers, implement firewalls and virus scanners, and train users to be cautious of opening files from questionable sources (even those tempting image files). 

If an infection does occur, have a plan in place to handle any security breaches or theft of private property that includes removal, such as with a malware removal tool, like Malwarebytes, TotalAV, etc. 
