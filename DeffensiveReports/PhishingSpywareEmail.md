# PCAP Phishing Email - Malware Investigation

<b>INCIDENT REPORT: JA-16651-MalwareInvestigation </b>

## Executive Summary 
Opening a suspicious email resulted in banking information being compromised and the bank account being hacked. Poor grandma.

## Methodology 
- VirusTotal.com > scan the PCAP file.
    - Detail tab to find the name of the Trojan
    ![VirusTotal Details](https://github.com/serengetijade/Cyber_Security/blob/main/img/PhishingSpywareName.jpg)

- WireShark Version 4.0.3    
    Running on Linux 6.1.0-kali5-amd64, with 12th Gen Intel(R) Core(TM) i7-12700H
    - Filter: kerberos.CNameString    
    Get username
    - Filter: bootp    
    Dynamic Host Configuration Protocol (Inform) > Option: (12) > Get host name
    - Filter: http contains “POST”    
    The only post requests are made to h1.wensa.at
    - Filter: frame contains “gzip”
    - Filter: (http.request or tls.handshake.type == 1) and !(ssdp)
    - Create a custom column: Server Name
        - Fields value: tls.handshake.extensions_server_name
        - Field occurrence: 0
    - Filter: (http.request or tls.handshake.type == 1) and !(ssdp)

## Findings/Results 
Malware Type: Spyware Trojan and Botnet

Trojan Name: Ursnif

Server: icemaiden.com

### Attack Narrative 
The traffic patterns suggest the website h1.wensa.at was called while the user was visiting mail.aol.com, e.g. while they were reading their email. The malware prompted the user to log in to her bank account at Bank of America, collected her details, and then posted them back to the malicious address. 

### Victim details 
IP address: 10.18.20.97

MAC address: Acer_56:9b:cf (00:01:24:56:9b:cf)

Host Name: Juanita-Work-PC

User account name: JUANITA-WORK-PC$S

User account name: momia.juanita 

### Indicators of compromise (IOCs) 
The user accessed her email, then POST requests were made to h1.wensa.at. Shortly after, the user logged in to her bank, secure.bankofamerica.com.

![VirusTotal Details](https://github.com/serengetijade/Cyber_Security/blob/main/img/PhishingSpywareIOC.jpg)

### Malicious HTTP traffic 
![VirusTotal Details](https://github.com/serengetijade/Cyber_Security/blob/main/img/PhishingSpywareHTTP.jpg)

### Suspicious domains using HTTPS traffic 
Host Name: h1.wensa.at

IP address: 8.208.24.139

MAC address: Dst: Cisco_93:a6:84 (00:07:50:93:a6:84)

## Conclusion 
The Ursnif malware is a banking trojan, stealer, and spyware usually attached to emails. The user triggered the spyware while she was checking her email. An antivirus software would block this sort of harmful traffic. 
