# Malicious Email
<b>INCIDENT REPORT: JA-16625-MaliciousEmail </b>

## Executive Summary 
Hackers often impersonate legitimate entities in order to infect systems with malicious code. Phishing is a type of cyber attack that attempts to represent itself as a legitimate person or entity for the purpose of identity/credential theft. Phishing may be via email, phone call, direct message, or elsewise.

A popular phishing attack pattern is to impersonate a financial entity, such as American express, and ask the user to validate their personal information, capturing it in the process. Or the attack may be to impersonate that same institution in order to get the user to click on and activate a harmful payload. 

## Methodology 
- Mozilla Thunderbird-  a free email application with added security filters. 
    - Download Thunderbird and extract the files. 
    - In the root CLI, enter command: sudo apt-get install thunderbird     
        This will install Thunderbird with the package manager and then the app can be access from the Applications menu within Kali Linux
    - Import the infected email(s) and view the email source code
- WireShark Version 4.0.3  
    Running on Linux 6.1.0-kali5-amd64, with 12th Gen Intel(R) Core(TM) i7-12700H
    - Filter: nbns		
        - Info → Registration NB ‘Hostname’ 
        - Ethernet II → Src = the MAC address
        - Internet Protocol Version → Src = IP address

## Findings/Results 
### Attack Narrative 
The host computer was infected through a malicious email. 

<i>Email details:</i>
- Date and time of infection: Fri, 6 Nov 2015 20:24:50 UTC
- From: "American Express Alerts" <AMEXPGNEUSCN0006006@verizon.net>S
- Subject: Important Information About Your Card Membership!

### Victim details 
IP address: 10.3.66.103
MAC address: Dell_2d:90:81 (00:24:e8:2d:90:81)
Host name: STROUT-PC<20>
User account name:
Ethernet II, Src: , Dst: Broadcast (ff:ff:ff:ff:ff:ff)

### Indicators of compromise (IOCs) 
Thunderbird flagged an email for malicious content. 

![Malicious Email](https://github.com/serengetijade/Cyber_Security/blob/main/img/MaliciousEmail.jpg)

### Malicious HTTP traffic 
IP address: 134.96.214.28
Host name: e-gf-a.htw-saarland.de
Sent: Fri, 6 Nov 2015 19:47:06 -0000

## Conclusion 
Users should be trained to spot potentially fraudulent communications. Scanners can be installed to check emails, hardware, usb dives, and other network access points. Thunderbird is an open source, free, email scanner that can detect and protect against harmful content.
