# Cyber Security
This repository is to highlight work as part of a cyber security projects that implemented penetration testing and incident analysis. The included project excerpts demonstrate cyber security prinicples such as protecting databases and keeping the back end secure, developing secure software and apps, protecting user data, and identifying vulnerabilities in existing applications. 
<br><div align="center">
![Virus Total](https://github.com/serengetijade/Cyber_Security/blob/main/img/VirusTotal.jpg)
![HybridAnalysis](https://github.com/serengetijade/Cyber_Security/blob/main/img/HybridAnalysis.jpg)
<br> 
![KaliLinuxBadge](https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white)
![Windows OS](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
</div>

## Skills
- Security Auditing
  - Attack Analysis
  - Penetration Testing
- Wireshark
- Burp Suite
- Virus Total
- Hybrid Analysis
- Malwarebytes 
- Virtual Box Virutal Environments
- Kali Linux
- Docker

### Security Auditing
<i>Attack Analysis</i>
<br>Real-world security breaches were analyzed to identify network access points, the type of malware used, and other attack details. PCAP files and security logs were examined using various softwares -discussed below- in order to figure out how hackers implemented the malware and what the malware was doing. 

<i>Penetration Testing</i>
<br>The [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) web application was used as a testing playground to exploit vulnerabilities most common in unsecure systems. Various techniques were applied, such as SQL injection, Cross Sight Scripting XSS, priviledge escalation, request interception, and more. Please see below for more specific information. 

### Wireshark
WireShark is a network analysis tool that is especially useful for cyber security operations analysts. It is a free and open-source packet analyzer. It is used for network troubleshooting, analysis, software and communications protocol development, and education.

### Burp Suite, by Portswigger
As a cyber security professional, it is essential to be familiar with penetration and vulnerability testing software. One of the most popular available is Burp Suite. It was used for intercepting network traffic, modifying the HTTP request data sent to the web server, injecting payloads, and testing responses.

### Virus Total and Hybrid Analysis
[Virus Total](https://www.virustotal.com/) and [Hybrid Analysis](https://www.hybrid-analysis.com/) are two online scanners that analyzes files and URLs for viruses, worms, trojans and other kinds of malicious content. Hybrid Analysis is useful for older types of maleware. 

### Malwarebytes
Malwarebytes is an anti-malware software for Microsoft Windows, macOS, ChromeOS, Android, and iOS that finds and removes malware. 

### Virtual Box Virtual Environments
VirtualBox is software for virtualizing the x86 computing architecture to run virtual environments. It allows for potentially malicious software to be explored in a contained, isolated environment without infecting the main host computer. 

![KaliLinuxVirtualBox](https://github.com/serengetijade/Cyber_Security/blob/main/img/VirtualBox.jpg)

### Kali Linux 

Kali Linux is an OS dedicated to ethical hacking. It has a collection of security and forensics tools. It was deployed within Virtual Box to text for malware. 
Version: Linux 6.1.0-kali5-amd64.

### Docker
Docker is an open platform for developing, shipping, and running applications. It was utilized to deploy Kali Linux and other virtual environments. 

## Sprint Overview
During a two-week sprint, my tasks were to analyze security breaches as well as test applications for vulnerabilities. I was responsible for finding malware and how it was introduced to the network, as well as performing ethical hacking techniques to identify security weaknesses in an online retail application. The sprint used real-world security exploitations and [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) web application. Specific tasks were assigned by the sprint leader, to be completed within a certain timeframe and meeting set parameters.

- Sprint duration: 2 weeks
- 23 stories completed
- Daily stand-ups
- Weekly code retrospectives
- Discord for chat and troubleshooting

![Azure Assignment](https://github.com/serengetijade/Cyber_Security/blob/main/img/Azure.jpg)

## Defensive Incident Reports
- [Phishing and Spyware Email](https://github.com/serengetijade/Cyber_Security/blob/main/DeffensiveReports/PhishingSpywareEmail.md)
- [Attack Vector Investigation: Botnet](https://github.com/serengetijade/Cyber_Security/blob/main/DeffensiveReports/AttackVectorInvestigation.md)
- [Ransomware Attack](https://github.com/serengetijade/Cyber_Security/blob/main/DeffensiveReports/RansomwareAttack.md)
- [Malicious Email](https://github.com/serengetijade/Cyber_Security/blob/main/DeffensiveReports/MaliciousEmail.md)
- [Linux server log analysis (Shell Injection)](https://github.com/serengetijade/Cyber_Security/blob/main/DeffensiveReports/LinuxLogs-ShellInjection.md)
- [Network Access Investigation - PCAP packet analysis](https://github.com/serengetijade/Cyber_Security/blob/main/DeffensiveReports/NetworkAccessInvestigation.md)
- PCAP Exploitation Kit identification
- PowerShell script analysis
- Malware traffic 
- Adware identification and removal

## Offensive Attack Reports
- [Authorization Escalation](https://github.com/serengetijade/Cyber_Security/blob/main/OffensiveReports/AuthorizationEscalation.md)
- Access restricted admin pages
- Modify HTTP GET request to access user accounts
- XSS Attack - Cross Site Scripting
- Null byte character injection
- Access "obscured", but unsecured folders
- CAPTCHA exploitation
- Brute force attach to discover passwords
- SQL injection to login under any credentials

## Additional Sources and Credits
- [OWASP](https://owasp.org/): The Open Worldwide Application Security Project® (OWASP) is a nonprofit foundation that works to improve the security of software. The OWASP Juice Shop is an awareness, training, demonstration and exercise tool for security risks in modern web applications. 