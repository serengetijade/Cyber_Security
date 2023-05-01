# INCIDENT REPORT: JA-16649-AdminAccess

## Executive Summary 
Users can have varying roles that allow them to access different areas of a site. Having an Admin access level allows users to access confidential site information. 

## Methodology 
- Docker
- BurpSuite
    - Proxy server
    - Repeater: change the POST request to modify the database and add role:admin rights.

## Findings/Results 

### Attack Narrative 
Without administration rights, trying to access #/administration page, results in error 403 message: 
![403 page](https://github.com/serengetijade/Cyber_Security/blob/main/img/AuthEscalation-403.jpg)
    
Pages that require administrative privileges can be temporarily accessed by replacing the token of a known admin to the session of any user: 

![Auth Token](https://github.com/serengetijade/Cyber_Security/blob/main/img/AuthEscalation-Token.jpg)

However, to add permanent administration rights, the “role” must be set to “admin”. This is done by using Burp Suite to capture the login attempt, and send it to the Repeater. 

![Auth Token](https://github.com/serengetijade/Cyber_Security/blob/main/img/AuthEscalation-POST1.jpg)

In the Repeater, the POST request can be modified: 
the POST url is changed from POST /rest/user/login to POST /api/users, 
and “role”:”admin” is added to the message body. 
![Auth Token](https://github.com/serengetijade/Cyber_Security/blob/main/img/AuthEscalation-POST2.jpg)

### Conclusion 
Authorization is security restrictions on user activity; different credentials have different levels of authorization. When a hacker can alter the database and give themselves administrative authorizations, it gives them permission to perform activities that would otherwise not be available to general users. Those activities are anything and everything an administrator would do, which is often an extensive list - from changing application details, accessing (and stealing) private information, deleting entire databases, and more. 

There are several ways that access of information can be restricted using access authorization, including these examples:
- Requiring a user to utilize a password,
- Having two-factor authorization, 
- Limiting administrative activities to certain devices,
- Utilizing a facial ID scan to unlock an app,
- Ensuring the use of a VPN, etc.

It is very important to protect the functions of the application, especially any private information of its users.   
