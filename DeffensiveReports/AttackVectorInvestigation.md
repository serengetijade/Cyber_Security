# Attack Vector Investigation: Botnet 
<b>INCIDENT REPORT: JA-16650-FindTheCulprit </b>

## Executive Summary 
A computer was infected through an unknown channel and this report examines the PCAP files to determine details of the infection. 

Seemingly harmless resources, such as .jpeg images, can contain malicious code. While the image may appear to be perfectly normal, the attack method takes advantage of “hidden” data that comes along with an image, data which isn’t translated into the image but usually contains the metadata about the image. This technique is known as steganography - the practice of hiding one file in another.

## Methodology 
- VirusTotal.com and Hybrid Analysis
- WireShark Version 4.0.3    
    Running on Linux 6.1.0-kali5-amd64, with 12th Gen Intel(R) Core(TM) i7-12700H
    - Filter: bootp    
    Select packet with “DHCP Request” listed in the info, then    
    Dynamic Host Configuration Protocol > Option: (12) Host Name
    - Filter: http.request    
    Examine the request header to find the OS
    ![OS in Header](https://github.com/serengetijade/Cyber_Security/blob/main/img/AttackVectorOS.jpg)
    - Export Object > HTTP
        - scan the largest files using VirusTotal.com
    - Filter: ip contains “config.jpg”
    - Filter: !(tcp.port eq 80) and tcp    
    Discover that there are NO requests coming from ports other than port 80. 
- Google search for the malicious IP and port number, “193.23.181.155 port 80”. The search results return a report from Hybrid Analysis:
  ![OS in Header](https://github.com/serengetijade/Cyber_Security/blob/main/img/AttackVectorGoogle.jpg)    
    Within the HybridAnalysis report, there is the SHA-256 code of the malware file: 8ba3149c7f9a8e2d1cdb55369e80e120e57401f699f71839035a0f8970c27459.
- Input the SHA-256 of the malware into VirusTotal.com: The report Details page indicates the file originated from the host name yandex.ru.
    ![OS in Header](https://github.com/serengetijade/Cyber_Security/blob/main/img/AttackVectorVirusTotal.jpg)
- VirusTotal: scan the PCAP File
    - Details Tab: 
        - HTTP Requests lists a domain, classicalbitu.com, that appeared in the PCAP files. It lists the file gate.php as malicious. 
        ![VirusTotal details tab](https://github.com/serengetijade/Cyber_Security/blob/main/img/AttackVectorDetails.jpg)
        - Snort Alerts and Suricata Alerts
        ![Trojan name](https://github.com/serengetijade/Cyber_Security/blob/main/img/AttackVectorName.jpg)
- Wireshark 
    - Filter: ip contains “gate.php”    
    The filter does show the file was present.
    - Filter: http.request    
    Examine activity leading up to the first call to classicalbitu.com. The activity, together with what was learned from the google search, makes it possible to infer the attack vector. 
    ![WireShark filter results](https://github.com/serengetijade/Cyber_Security/blob/main/img/AttackVectorWireshark.jpg)

## Findings/Results 
Date: Tuesday, 22 Sep 2015 22:41 UTC

Infected file name: config.jpg

Infected file type: jpeg image

SHA-256 of infected file (jpeg): 3359a8d15eb9de2e6a9d5a91182ae41f7dda053e78f5e9d3b715ab28afa57ea1

Malware type: Trojan

Malware name: Zeus Trojan

Malware SHA-256: 8ba3149c7f9a8e2d1cdb55369e80e120e57401f699f71839035a0f8970c27459

### Attack Narrative 
On Tuesday, 22 Sep 2015, at 22:41 UTC, a GET request was made to a malicious address, classicalbitu.com. An image file, config.jpeg, was requested that contained Trojan malware. 

### Victim details 
IP address: 10.54.112.205

MAC address: HewlettP_01:db:2f (00:50:8b:01:db:2f)S

Host Name: Pendjiek-PC

Operating System: Windows NT 6.1

### Indicators of compromise (IOCs) 
When the TCP stream for the request to classicalbitu.com is opened, there is excess code displayed that wouldn’t be present in a .jpeg image. 
![Indicator of Compromise](https://github.com/serengetijade/Cyber_Security/blob/main/img/AttackVectorIOC.jpg)

### Malicious HTTP traffic 
![Malicious HTTP Traffic](https://github.com/serengetijade/Cyber_Security/blob/main/img/AttackVectorHTTP.jpg)

### Suspicious domains using HTTPS traffic 
Hostname: classicalbitu.com

IP address: 193.23.181.155

MAC address: Cisco-Li_09:2e:af (20:aa:4b:09:2e:af)

## Conclusion 
The user’s computer was infected with the Zeus Trojan. The two primary goals of the Zeus trojan horse virus are to steal financial information and add machines to a botnet. At this time, the origination of the malicious call cannot be determined, however evidence indicates the malware was hidden inside a prior email or attachment that was not part of the provided PCAP files and the user's computer was activated as a bot. 

Email attachments, jpeg images, and various documents can present an attack vector. Ways to protect your system include: 
- Email scanners and other virus scanners.
- Shutting down unused ports to limit attack vectors. 
- Setting up an IPS, a security router, or a VPN can all help protect against malicious traffic. 
