# Ransomware Attack
<b>INCIDENT REPORT: JA-16627-RansomwareAttack </b>

## Executive Summary 
Ransomware is a type of malware that encrypts user files until a fee is paid. Jigsaw is ransomware that uses the AES algorithm to encrypt various files stored on computers. Targeted files include .jpg, .docx, .mp3, .mp4, and many others.

## Methodology 
- Virtual Box
    - Windows 10 virtual environment
- Identify the ransomware: google search for the ransom message
    - Jigsaw Ransomware
- Task Manager > stop the application “Firefox”
- Run OS in safe mode
    - Run > MSConfig > Boot > Safe boot
- File explorer: 
    - search for “jigsaw” and delete any files, such as .exe file.
    - search for files containing “drpbx” and delete them.
    - remove any files containing “firefox” that are not system files (that are not protected by TrustedInstaller).
![File Explorer](https://github.com/serengetijade/Cyber_Security/blob/main/img/Ransomware-FileExp.jpg)

- Control Panel: System - See which processes start up automatically when you start Windows. Ensure that the malware does not appear, this ensures that it will not autorun. 
![System Startup](https://github.com/serengetijade/Cyber_Security/blob/main/img/Ransomware-Firefox.jpg)

- Disc Cleanup: Clear temporary files
    - ~~Temporary Files~~
    - ~~Temporary Internet Files~~

![Disk Cleanup](https://github.com/serengetijade/Cyber_Security/blob/main/img/Ransomware-DiskCleanup.jpg)

- Control Panel: Uninstall suspicious programs
Sort by recently installed applications and remove any suspicious programs to remove the potential entry point for the malware. 

- Jigsaw Decrypter
Download, install, and run a jigsaw decrypter, such as https://www.bleepingcomputer.com/download/jigsaw-decrypter/ 


## Findings/Results 
### Attack Narrative 
Ransomware, such as Jigsaw, is often distributed through emails and email attachments. Jigsaw is a typical data locker ransomware whose aim is to blackmail users into paying a ransom for decryption of data. 
Files are encoded and renamed with .fun extension. Files that may be encrypted include: 
- Audio files
- Video files
- Document files
- Image files
- Backup files, etc

A ransom message appears with a description of the ransom, and a request to pay.

## Indicators of compromise (IOCs) 
Upon startup, a ransom message appears. Files are encrypted, and one file every hour is deleted. 

![Ransom Note](https://github.com/serengetijade/Cyber_Security/blob/main/img/Ransomware-Note.jpg)

## Decryption
Free decryption tools are available for download, such as https://www.bleepingcomputer.com/download/jigsaw-decrypter/ 

![Decryption Tool](https://github.com/serengetijade/Cyber_Security/blob/main/img/Ransomware-Decrypter.jpg)

## Conclusion 
The Jigsaw ransomware infected the computer via a malicious email attachment. 

Users should be trained not to open unexpected attachments, especially .rar or .zip archive types. Malware is often sent as emails and attachments that are meant to mimic legitimate sources, so training on threat prevention is important and effective. 

Firewalls and malware scanners also reduce the risk of attack. In Windows Security, turn on the Firewall & network protection and the App & browser control. 
