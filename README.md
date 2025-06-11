# Ethical-Hacking-Lab

This is my project which demonstrates Ethical Hacking Simulation & Incident Analysis


## Abstract:
The general population is witnessing cyber-attacks regularly while just sitting back and watching them unfold while the security defenders and cybercriminals are in a perpetual rat race to outperform each other. The internet is a tricky place to be in, yet it is a key aspect of everybody’s lives, as many of us depend on it daily. The increased attack surface for the attackers brings in a lot for security professionals to take in, there must also be responsibility for the users to maintain safe practices in the cyber field. This project showcases the importance of how a vulnerable machine could lead to getting all the “interesting” information with a hacker’s mindset and provides necessary recommendations for mitigating these risks. For demonstration purposes, this is performed in a controlled environment such as Metasploitable 2 - an inherently vulnerable machine - and employing Kali Linux VM to simulate ethical hacking techniques, I call attention to these issues with a hacker's mindset and provide insights into effective cybersecurity practices.    

## Introduction: 
The main goal of this project is to carry out a complete analysis of the popular techniques used by ethical hacker, as well as types of cyber-attacks and to perform the different types of assessments in a safe way, using tools like Metasploitable 2 (a vulnerable virtual machine) that will be the target and Kali Linux virtual machine (dedicated to performing ethical hacking techniques). By means of these tools, the red team simulation will be demonstrated, and the effectiveness of the ethical hacking strategy will be measured. In this project, I conducted an elaborate evaluation of my hypothesis of how a vulnerable machine in any kind of environment is a hazard and how easy it is for attackers to gain remote access.
	Most of the work involves mapping critical vulnerabilities, simulating attacks, and analyzing the results of ‘penetration testing’ against the target system. Penetration system is an exercise carried out by security experts to find and exploit vulnerabilities in a target computer system. The techniques performed in this project will strictly adhere to the ethical guidelines and stick with the best practices to assess the hacking strategies.
	This research will focus on advancing understanding and improving existing practices in two areas: how to evaluate the outcomes of red teaming exercises; and the weaknesses of a critical infrastructure to hacks, attacks, and accidents; and how ethical hackers should set the rules and norms when working to penetrate private networks.

## Literary Review
The following sources provided key insights and knowledge that informed the develop-
	ment and execution of this project:

* Metasploitable 2 Walkthrough by Hacking Loops: The article by Hacking
Loops presented an in-depth analysis of Metasploitable 2 and its inherent vulnerabil-
ities. The walkthrough offered a comprehensive overview of potential attack vectors
and scenarios, which were valuable for understanding the target environment and
preparing for penetration testing.
* EC-Council’s 5 Phases of the Penetration Testing Process: The 5 phases
outlined by EC-Council is incorporated as the penetration testing process used
in this project. These phases (reconnaissance, scanning, vulnerability assessment,
exploitation, and reporting) provided a structured approach to simulate cyberattacks
against the target system, helping identify and address vulnerabilities.
* Metasploit: The Penetration Tester’s Guide: The book ”Metasploit: The
Penetration Tester’s Guide” by David Kennedy, Jim O’Gorman, Devon Kearns,
and Mati Aharoni offered valuable insights into the reasoning behind performing
penetration testing and utilizing the Metasploit framework. This guide’s detailed
explanations of exploit creation and usage enhanced the project’s approach to ethical
hacking and exploitation using Metasploit framework which was first developed by
H.D. Moore for creating and developing exploits.
* Red Team Fundamentals on TryHackMe: The ”Red Team Fundamentals”
room on TryHackMe provided practical modules for understanding and applying
red teaming strategies, enhancing hands-on experience in simulated cyber-attacks.
* MITRE ATT&CK Simulator on TryHackMe: The ”Threat Modelling” room
introduced the MITRE ATT&CK simulator, contributing to the understanding of
adversary tactics, techniques, and procedures (TTPs) in a controlled environment.
* Red Team Guide: The ”Red Team Guide” offered insights and resources for
red teaming methodologies, aligning with psychological aspects explored in Micah
Zenko’s work.

These sources laid a solid foundation for the project, guiding the design and execution
of penetration testing and ethical hacking simulations. The knowledge and methodologies
provided by these sources contributed to the project’s success and its ability to effectively identify and address cybersecurity vulnerabilities.

## Research Questions and Methods

This section discusses the main research questions tackled in this project and the methods used to investigate them. The project was centered on ethical hacking practices in a controlled setting, with the goal of understanding cybersecurity weakness and exploitation techniques.

## Research Questions

The project aims to explore the following research questions: 

1.	What vulnerabilities exist in the Metasploitable 2 VM, and how are useful for a hacker? 
2.	How impactful are these vulnerabilities in terms of security and resilience of the target system against these attacks? 
3.	What steps can be taken to address identified vulnerabilities, mitigate them and enhance security? 

## Methods

The project utilized a controlled environment for experimentation, focusing on the following phases of penetration testing:

1. Reconnaissance: The initial phase involved gathering information about the target system (Metasploitable 2) using tools such as Nmap and Wireshark to understand the network architecture and identify potential vulnerabilities.

2. Scanning: Scanning techniques were applied to probe the target system and identify open ports, services, and potential weak points. This phase utilized tools like Nmap and Nessus to perform thorough assessments.

3. Vulnerability Assessment: The project leveraged Nessus and other tools to evaluate vulnerabilities in the target system, including outdated software, weak authentication methods, and insecure configurations.

4. Exploitation: In this phase, ethical hacking techniques were applied to exploit identified vulnerabilities using tools such as Metasploit. This stage demonstrated how attackers could leverage vulnerabilities to gain unauthorized access.

5. Reporting: Findings from each phase were documented and analyzed to assess the effectiveness of red teaming exercises and the impact of identified vulnerabilities. Detailed reports included remediation strategies and recommendations for enhancing security.

	These methods provided a comprehensive approach to exploring the hacker's mindset, demonstrating the importance of adhering to ethical standards during penetration testing, and offering valuable insights into securing systems against potential cyber threats.
Results:

Here is the walkthrough of the penetration testing stages. 
In this project, I divided the process into 5 stages namely:
* Reconnaissance
*	Scanning
*	Vulnerability Assessment
*	Exploitation
*	Reporting

### 1.	Reconnaissance:
In simple terms, reconnaissance means information gathering about the target system. There are two types of reconnaissance: Passive and Active reconnaissance. The attacker will be active while there is an interaction with the target during active reconnaissance whereas the attacker may be inactive during a passive reconnaissance. 
In this assessment, I focused on active reconnaissance as I (attacker) am actively engaging with the target system. Some of the tools to perform active recon are telnet, ping, traceroute. These are the observations using ping and traceroute.
![image](https://github.com/user-attachments/assets/2017e897-66a6-44ba-af21-daaf30e47171)
  
*Figure 1: IP address of Metasploitable VM.*

 ![image](https://github.com/user-attachments/assets/195ec853-0107-4dfb-8354-0396eb5c3e2b)
   
*Figure 2: ping and traceroute.*
  
The ping command confirms whether the target system is connected and in reach, measures network latency and stability. The traceroute command maps the network path to the target system and identifies each hop along the way. It helps to identify network infrastructure so we can discover any routers or switches along the way. 
I performed arp-scan to list all devices connected to the network. ARP stands for Address Resolution Protocol. ARP scanning identifies other active hosts on the network. 
 ![image](https://github.com/user-attachments/assets/2d8f2e31-f99c-46a9-a142-e51378194300)
   
*Figure 3: ARP scan.* 
  
The telnet command is used to attempt connections to specific ports and whether they are open. I monitored those connections using Wireshark and started capturing the packet data while attempting to log in to Metasploitable VM. 
 ![image](https://github.com/user-attachments/assets/81b8cf05-accb-40fc-915a-9e6b92337d8f)
   
*Figure 4: telnet.*
  
Through the pcap analysis, and following the TCP stream leads to the discovery of credentials used for a successful log in. This is also called telnet credential harvesting. In the pcap file, the password is delivered letter by letter. The color red in the image indicates input and the blue indicates output visible on the terminal. The credentials were transmitted in plain text, highlighting the lack of encryption.
![image](https://github.com/user-attachments/assets/296501ce-bce5-4081-9aa0-9e71b8925292)
  
*Figure 5: Wireshark capture during the login attempt.*
  
### 2.	Scanning:
After the information gathering stage, we move to the scanning phase. In this stage, we understand how the target application or service works. Nmap is one of the best tools to scan for web applications and their structure, particularly URLs, endpoints, and potential access points. It identifies the services running on open ports and their versions and also focuses on specific services that could be exploited, such as web servers, FTP servers, or databases. In other words, Nmap is very useful for service scanning, version scanning, and operating system detection.
![image](https://github.com/user-attachments/assets/203e7558-558d-4d36-9647-9617ea0c161b)
  
 *Figure 6: Nmap scan.*
  
### 3.	Vulnerability Assessment:
 ![image](https://github.com/user-attachments/assets/0d562c78-ca89-4161-84e3-99e3bf820b43)
  
*Figure 7: Nessus report of vulnerabilities by host.*
  

 ![image](https://github.com/user-attachments/assets/82271c19-6965-40c9-98dd-c174c5994bc5)
   
*Figure 8: Nessus Network Scan Results*
  
After scanning for open ports using Nmap, to get a better understanding of the ports and their vulnerabilities, I used Nesses, a vulnerability scanner application to get the overview of the Metasploitable vulnerabilities. The Nessus scan of the VM IP address (192.168.237.128) identified 123 total vulnerabilities which includes a range of critical, high, medium, low, and informational issues. The key findings are as follows:
  
Critical Vulnerabilities:
* Apache Tomcat Request Injection: Allows request injection.
*	Bind Shell Backdoor: Unauthorized remote access.
*	SSL Version 2 and 3: Outdated protocols prone to attacks.
*	Unsupported Unix OS: Potential vulnerabilities due to lack of updates.
*	NFS Exported Share: Publicly accessible NFS shares.
  
High Vulnerabilities: 
*	ISC BIND Downgrade/DoS: Potential for denial-of-service attacks.
*	Samba Badlock: Remote code execution risk.
*	SSL Weak Cipher Suits: Use of weak encryption (SWEET32).
  
Medium Vulnerabilities:
*	SSL Certificate Issues: Self-signed or expired certificates.
*	HTTP TRACE/TRACK Methods: Could facilitate cross-site tracing attacks.
*	SMB Signing: Not required, exposing the system to man-in-the-middle attacks.
  
Low Vulnerabilities: 
*	SSH Weak Algorithms: Weak MAC and key exchange algorithms.
*	SSL/TLS Weak Cipher Suites: Vulnerable to known attacks like Logjam.

Informational findings: 
Service versions and open ports such as FTP, HTTP, and Telnet were detected, along with system software details.
The above vulnerabilities could lead to exploitation of target system’s security posture. Prioritization of critical vulnerabilities is recommended for immediate action.

### 4.	Exploitation:
**Port 21 FTP:**
To make things easier and for the purpose of demonstration, I created a users.txt file and passwords.txt containing very few common usernames and passwords respectively. Used Hydra to attack the target system with the users and passwords list. Upon finding valid passwords, I connected to the FTP open port and entered one of the valid passwords resulting in gaining access to the target system.
  
![image](https://github.com/user-attachments/assets/fe3b0836-b0d2-40fb-9b79-5f5919d10aba)
  
*Figure 9: Connecting via FTP*
  
Exploiting VSFTPD v2.3.4:
In the Nmap scan of the target system, the service running on port 21 is vsftpd v 2.3.4. 
![image](https://github.com/user-attachments/assets/0e0c29c7-9f61-45ce-81ea-7933185fb18b)
  
*Figure 10: Nmap scan of open FTP port.*
  
Vsftpd stands for Very Secure FTP Daemon. The vsftpd v2.3.4 exploit leads to backdoor command execution (CVE-2011-2523)
  
![image](https://github.com/user-attachments/assets/d1f233a0-9bbc-4190-849d-61ce70e52581)
  
*Figure 11: Search VSFTPD v2.3.4*
  
![image](https://github.com/user-attachments/assets/f7f4c08a-3f47-4b6d-80d0-124ccc3d644d)
  
*Figure 12: set RHOSTS to Metasploitable VM IP.*
  

![image](https://github.com/user-attachments/assets/4899f273-5abb-4353-993d-e3ba51aba87c)
  
*Figure 13: running the vsFTPd 2.3.4 backdoor.*
  
```msf > search vsftpd
   ...VSFTPD backdoor command injection...
msf > use exploit/unix/ftp/vsftpd_234_backdoor
msf exploit(vsftpd_234_backdoor) > show options
    ...show and set options...
msf > set RHOSTS <Metasploitable VM IP>
msf exploit(vsftpd_234_backdoor) > run
         . . .Access to the target system. . .
```

By running the above backdoor, we can conclude that an FTP server is listening on the remote port.

**Port 1524 Bindshell:**
  
Bind shell is a setup type where remote consoles relate to other computers over the network. In Bind shell, an attacker launches a service on the target system, to which the attacker can connect. It is usually on port 1524.
Exploiting Bind Shell Backdoor:
![image](https://github.com/user-attachments/assets/2181687f-fecf-44be-92c9-ca7b704b8154)
  
*Figure 14: Connecting via netcat on port 1524.*
  
For this, just using netcat or telnet, Bind Shell backdoor can be exploited without the use of Metasploit.
 
**Port 22 SSH:**

In Metasploit, ssh_login is used to brute-force guess SSH login credentials.

![image](https://github.com/user-attachments/assets/b59b33fa-b73a-4cda-9314-2e81dde94283)
  
*Figure 15: Setting ssh_login exploit options*
  
Using the auxiliary/scanner/ssh/ssh_login module, Port 22 can be used to gain access to the target system.
![image](https://github.com/user-attachments/assets/2d8d4f49-31b4-4ffc-92b4-1e9a14ab81f8)
  
*Figure 16: Creating session with the target system.*

```msf > search ssh_login
   ...SSH Login Check Scanner...
msf > use auxiliary/scanner/ssh/ssh_login
msf auxiliary(scanner/ssh/ssh_login) > show options
    ...show and set options...
msf > set RHOSTS <Metasploitable VM IP>
msf > set USER_FILE Users.txt
msf > set PASS_FILE Passwords.txt
msf > set stop_on_success true
msf auxiliary(scanner/ssh/ssh_login) > exploit
         . . . Session created with the target system. . .
```
![image](https://github.com/user-attachments/assets/7e230b0b-86da-44f1-81f0-c07f799bf924)
  
*Figure 17: Gaining access through the target's shell.*
  
By using the above exploit, we gained access to the VM through port 22 ssh. Port 23 Telnet can also be exploited in the same way by using “auxiliary/scanner/telnet/telnet_login”.
  
**Port 25 SMTP:**
SMTP stands for Simple Mail Transfer Protocol. Metasploit has a user enumeration module for SMTP. We can use VRFY to verify users.
  
![image](https://github.com/user-attachments/assets/3caa1611-20f6-4ffb-8f9d-4941ef2f5ac4)
  
*Figure 18: Verifying users using netcat on port 25.*
  
smtp_user_enum is a user enumeration tool which can guess usernames on a SMTP service.
![image](https://github.com/user-attachments/assets/5acc43eb-8a4b-438a-a890-16f7491a7e3b)  
  
*Figure 19: Verifying users on SMTP server.*
  
The above command is verifying (-M VRFY) the search for mentioned user (-U Users.txt) on the target server (Metasploitable VM IP) hosted on SMTP.
Port 139 & 445 NetBIOS Session:
The service running on ports 139 and 445 is SMB (Server Message Block) protocol’s re-implementation which is the Samba software. NetBIOS is used for file sharing and name resolution.
Exploiting Samba:
 ![image](https://github.com/user-attachments/assets/2d44b8be-4f31-4598-8cb7-b407776577e7)
   
*Figure 20: exploit module used for Samba.*
  
The Samba usermap_script is used as a command execution vulnerability in Samba versions 3.0.20 through 3.0.25rc3. The version running on those ports is in the range of 3.x to 4.x. To exploit this vulnerability, there would be no authentication.
 ![image](https://github.com/user-attachments/assets/f8b613ec-6c16-49e0-a19b-6365c80cc1c0)
   
*Figure 21: Setting options for the Samba exploit.*
  
Running the samba exploit gave root access. Further, after gaining shell access and changing session. Since I got the root access, I can use the post/linux/gather/hashdump module. This module dumps the password hashes for all users on a Linux System.
![image](https://github.com/user-attachments/assets/45b355d7-a82e-4102-8781-c7fe9b3bcdc5)
  
*Figure 22: Using post/linux/gather/hashdump module.*

![image](https://github.com/user-attachments/assets/c67cbb47-4e1c-451e-89a3-b40a1ab57ab9)
  
*Figure 23: Dumping the password hashes for all users.*
  
After running the exploit, we are provided with unshadowed password file which contains the password hashes. I then used “John the Ripper” to crack the password hashes using single mode.
It will crack the password hashes for each username. The password hashes are in the ‘/home/kali/.msf4/loot/20240415140807_default_192.168.237.128_linux_hashes_0.32622.txt’ location.
  
![image](https://github.com/user-attachments/assets/318f96d6-6623-48b5-8924-ddc84ba4a9ad)
  
*Figure 24: Password cracking using the John the Ripper.*

``` msf > use exploit/multi/samba/usermap_script
msf > set RHOSTS <Metasploitable VM IP>
msf auxiliary(scanner/ssh/ssh_login) > exploit
         . . . Session created with the target system. . .
```

**Port 5900 VNC:**
VNC stands for Virtual Network Computing, it allows remote access to GUI. 

![image](https://github.com/user-attachments/assets/e307b238-27e9-4e3c-8cb1-5d96bd62899a)
  
*Figure 25: Checking if port 5900 is open with Nmap.*

  
![image](https://github.com/user-attachments/assets/b9bf001b-f27b-4712-a5a9-f15ee761004f)
  
*Figure 26: Searching for vnc_login.*
  
![image](https://github.com/user-attachments/assets/59ecbe4f-2df8-499f-9eb8-2a9f61be9581)
  
 *Figure 27: Setting options for vnc_login exploit.*
   
![image](https://github.com/user-attachments/assets/f458ff63-b00c-4241-ae0f-730a09e9d2ff)
  
*Figure 28: Running exploit leads to successful login credentials.*
  
  
In this case, we got to know that there is a VNC server inside the metasploitable VM and we were able to use a default log in and password list that we have and we were able to find “password” as the password and the user name was revealed to be “root”.
Then with the given credentials, we can access the graphical user interface of the target system using vncviewer.
  
 ![image](https://github.com/user-attachments/assets/a6689725-9423-4ed4-939f-928ef085efdc)
   
 *Figure 29: Gaining GUI access of Metasploitable VM.*
   
### 5. Reporting:
Here is the breakdown of the exploits performed during the exploitation phase.
1.	FTP Exploitation (Port 21 – VSFTPD v2.3.4):
CVE: CVE-2011-2523
CVSS Base Score: 9.8 (CRITICAL) [Source: NIST NVD]
Description: The exploit targets a backdoor vulnerability in VSFTPD v2.3.4, which allows for remote code execution upon successful exploitation.
Remediation: Upgrade the FTP server to a version not affected by this vulnerability and disable the FTP service if not required.

2.	Bindshell Backdoor Exploitation (Port 1524):
CVSS V3.0 score: 9.8 (CRITICAL) [Source: Tenable Nessus VA Report]
Description: Exploiting a bindshell backdoor enables remote access and control over the target system, allowing the attacker to execute arbitrary commands.
Remediation: Disable the bindshell backdoor service or upgrade to a version of the service that is not affected by this vulnerability.

3.	SSH Exploitation (Port 22):
Description: Exploitation of SSH Vulnerabilities (for example: weak password authentication, unsupported versions) can lead to unauthorized remote access.
Remediation: Use strong, unique passwords for SSH authentication, and ensure that the server is running a supported version of SSH.

4.	Telnet Exploitation (Port 23):
Description: Exploiting Telnet with weak credentials allows unauthorized access to the target system, posing risks to data security and integrity.
Remediation: Disable Telent services if possible and replace them with more secure alternatives such as SSH for remote access.

5.	SMTP User Enumeration (Port 25):
Description: SMTP user enumeration can lead to gathering information about system users, potentially helping in attacks like password spraying.
Remediation: Configure SMTP servers to limit information disclosure during interactions and consider implementing authentication and access controls.

6.	Samba Exploitation (Port 139 and 445 – usermap_script):
CVE: CVE-2007-2447
CVSS v2.0 Base Score: 6.0 (Medium) [Source: NIST NVD]
Description: This exploit allows remote code execution through a script injection vulnerability in Samba’s usermap module.
Password Hash Cracking: While not a direct exploit, cracking password hashes can lead to unauthorized access if successful.
Remediation: Update Samba to a version not affected by this vulnerability and restrict user permissions. Use strong, unique passwords for Samba accounts and enable encryption for data transfer. 

7.	VNC Exploitation (Port 5900):
CVSS v3.0 score: 10.0* (CRITICAL) [Source: Tenable Nessus VA Report]
Description: Exploiting VNC vulnerabilities can lead to remote access to graphical desktop of the target system. The login password was “password”. 
Remediation:  Use strong, unique passwords for VNC authentication, and ensure that the server is running a supported version of VNC.

## Conclusion:
The penetration testing performed against Metasploitable VM draws several key conclusions and they are as follows:
Effective Reconnaissance and Scanning: Using effective tools combining active reconnaissance with tools like ping, traceroute, ARP scan, along with scanning phase with Nmap, provided comprehensive insights into the target system’s network and service space. This laid the groundwork for further development of assessment and exploitation stages.
Identified Critical and High-Risk vulnerabilities: Vulnerability assessment using Nessus revealed a range of vulnerabilities in the Metasploitable VM, including critical and high-risk issues like outdated SSL protocols, exposed NFS shares, and unauthorized remote access points. These vulnerabilities have the potential to compromise the majority of the attack surface.
Successful Exploitation of Key Services: Exploitation of services such as FTP (VSFTPD v2.3.4), bindshell backdoor, SSH, and Samba demonstrated how attackers could leverage known vulnerabilities to gain unauthorized access and control over the target system. This highlights the importance of patching and updating services regularly.
Credential Harvesting and Password Cracking: By monitoring connections with Wireshark and exploiting services such as Telnet, the experiment showcases how easy it is to harvest credentials since they are able to be captured in plain-text and passwords cracked using tools like John the Ripper. This recommends the need for stronger authentication methods and secure password practices.
Remediation Strategies: The report emphasizes the importance of implementing effective remediation strategies such as upgrading vulnerable software, disabling unnecessary services, and enforcing strong password policies, authentication methods, and encryption protocols. These measures are essential to mitigate the risks identified during the testing process.
Future Scope: Future work could focus on exploring other vulnerabilities, hardening techniques, and assessing different attack vectors. Further investigation into automated penetration testing and continuous monitoring would also be valuable.

In summary, the penetration testing performed against the Metasploitable VM provided great insights about the attack surface and the security posture of the target system. By identifying and exploiting many vulnerabilities, the project demonstrated the importance of routine security audits, assessments, timely software updates, and proactive defense mechanisms. These findings stress the need for security awareness for cyber security professionals and also general users.

## References:
-	[Metasploitable 2 - A Walkthrough of The Most Interesting Vulnerabilities](https://www.hackingloops.com/metasploitable-2/)
-	[Metasploitable 2 vulnerability assessment - Hacking Tutorials](https://www.hackingtutorials.org/metasploit-tutorials/metasploitable-2-vulnerability-assessment/)
-	[Ethical Hacking Deep Dive: Metasploit, Nmap, and Advanced Techniques - YouTube](https://www.youtube.com/watch?v=Ft6tLATCIVQ&ab_channel=NielsenNetworking)
-	[Metasploitable 2 – Finding Metasploitable with nmap – Security Aspirations](https://securityaspirations.wordpress.com/2017/06/25/metasploitable-2-finding-metasploitable-with-kali/)
-	[Metasploitable 2 | Vulnhub CTF | Metasploit | 2023 Walkthrough | Hindi - YouTube](https://www.youtube.com/watch?v=xTuttHtrBhs&ab_channel=Hack_The_Crack)
-	[Metasploitable 2 Writeup. This elaborates on pawning… | by !abdullah | Medium](https://medium.com/@iabdullah_215/metasploitable-2-writeup-muhammad-abdullah-52e89647efff)
-	[Metasploitable/SSH/Exploits - charlesreid1](https://charlesreid1.com/wiki/Metasploitable/SSH/Exploits)
-	[Penetration Testing Metasploitable2: A Hands-On Experience | by callgh0st | Medium](https://callgh0st.medium.com/how-i-hacked-metasploitable2-1a871257fd8c)
-	[Simple Penetration Metasploitable 2 (Cybersecurity) - YouTube](https://www.youtube.com/watch?v=LI4v7UDxxto&t=2s&ab_channel=LoiLiangYang)
-	[Milkad0/Metasploitable-2: Security audit of metasploitable 2](https://github.com/Milkad0/Metasploitable-2)
-	[techouss/Metasploitable2: hacking metasploitable v2](https://github.com/techouss/Metasploitable2)
-	[Simple Penetration Testing Tutorial for Beginners! - YouTube](https://www.youtube.com/watch?v=mMoJQDWP9qI&ab_channel=LoiLiangYang)



