This is a proof-of-concept demonstration of Linux privilege escalation to reproduce the HackingBuddyGPT results using the Metasploitable 2 virtual machine as the target.

In my testing with the Kali Linux VM, I executed the wintermute tool, which displayed the available commands for the LinuxPrivesc agent. The output included the sequence of commands issued and their respective results, such as user identity and sudo privileges.

![image](https://github.com/user-attachments/assets/8a9c7119-e14f-4917-b8cf-1ea9b46625f1)


To gain root access on the Metasploitable 2 VM, I entered the command sudo -i, which executed successfully, confirming that I obtained root privileges, as indicated by the prompt changing to root (root@metasploitable:~#).
  
![image](https://github.com/user-attachments/assets/271fa60a-3596-4023-af6d-eb09c0f45401)


