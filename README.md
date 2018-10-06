# Reckon
Is a simple wrapper script written in bash. It was written in preparation for the OSCP exam to help me be more time efficient during testing by automating some basic tasks and scans with a focus on enumerating the more targetable services like HTTP and SMB.

### Prerequisites
Reckon will run on any Kali Linux image and is currently wrapping multiple tools and scripts such as: Nmap, Nmap-NSE, Curl, Enum4linux, Nikto, and Dirb. Reckon shouldn't have issue running on other Linux distros provided these tools are present.

### Example Usage
``` ./reckon.sh 10.10.10.10 ```

``` ./reckon.sh scanme.nmap.org```

``` ./reckon.sh /home/user/hostlist.txt```

### Workflow
Reckon's work flow was designed to provide you with quick highlevel results prior to conducting slower and more thorough scans in the later stages. Again, the intent of this wrapper is to increase time efficiency by minimize downtime. So rather than waiting 20+ minutes for full TCP/UDP scans with multiple argments, Reckon performs the same scans incrementally while regularly updating results to the terminal for review.

### Reckon runs in five stages

* <b>Stage 1:</b> Directory Creation - Upon execution, a target directory will be created in the current working directory. The results of scans will be filtered, organized, and printed to terminal while copies of the scans results will be stored in the target directory.

* <b>Stage 2:</b> QuickScan - Using nmap --top-port arugement to scan for the top 100 common tcp ports. This scan is intended to give you quick results so you can descide where you would like to focus your attention (manual enumeration/research) while awaiting the results of pending scans in stage 3 and 4.

* <b>Stage 3:</b> VersionScan - Run an nmap version scan targeting the open ports previously identified in the quickscan. The scan will not only attempt to identify running services but also identify services running on non-standard ports. As example, a web server running on tcp port 1000 would be flagged and handled the same as port 80 or 443 in stage 4.

* <b>Stage 4:</b> EnumerationScan - Using the results from the quick scan and version scan, Reckon will begin running more aggressive scanners against the previously identified ports/services. Services are targeted in the following order: HTTP/HTTPS, SMB/NetBIOS/Samba, Other. Please note, in an attempt to prevent inaccurate results, DoS condictions, and general performance issues, Reckon only allows one instance of Nikto to run at a time however will create a scan queue so that Nikto is run against each port (or host) one at a time rather than similtaniously. This same consideration also applies to  dirb scans. 

* <b>Stage 5:</b> FullScan - After the scans for the top 100 tcp ports have completed, Reckon will begin targeting the remaining tcp ports and proceed through stages 2, 3, and 4 before completing (or moving to the next host if a host list was provided as an argument).

### Limitations
* Reckon is a basic script running mostly default scans for the scripts/tools it is managing. Reckon should not be used with the expection of replacing thorough enumeration.
* At this time, Reckon does not target UDP ports and/or services. 
* Adhears to all OSCP exam limitations: https://support.offensive-security.com/#!oscp-exam-guide.md
