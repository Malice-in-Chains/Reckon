# Reckon
Written by MaliceInChains

maliceinchains106@gmail.com

## Purpose
Reckon is simplistic wrapper script written in bash. It was written in preparation for the OSCP exam to help me be more efficient during testing by automating some basic common tasks and scans with a focus on enumerating the more targetable services like HTTP and SMB. 

### Prerequisites
Reckon was built to run on Kali Linux and is currently wrapping multiple tools such as nmap, curl, enum4linux, nikto, and dirb.  

### Example Usage
``` ./reckon.sh 10.10.10.10 ```

``` ./reckon.sh scanme.nmap.org```

``` ./reckon.sh /home/user/hostlist.txt```

### Workflow
Reckon's work flow was designed to provide quick highlevel results prior to conducting slower and more thorough scans in the later stages. Again, the intent of this wrapper is to increase time efficiency by minimize downtime. So rather than waiting 20+ minutes for full TCP/UDP scans with multiple argments, Reckon performs the same scans incrementally while regularly updating results to the terminal for review.

As shown in the example usage, Reckon can be used against a single target or multiple targets when provided a list of hosts. 

### Reckon runs in five stages

* <b>Stage 1:</b> Testing directory creation - Reckon will first create a target directory in the current working directory when executed. The results of future scans will be cleaned, organized, and printed to terminal. Copies of the full scans results will also be stored in the target directory.

* <b>Stage 2:</b> Conduct a quick scan - Using nmap --top-port arugement to scan for the top 100 common tcp ports. NOTE: Reckon will conduct a full tcp (all 65535 ports) scan later in stage 5. This quick scan is intended to give you nearly immediate results so you can descide where you would like to focus your attention (manual enumeration and/or research).

* <b>Stage 3:</b> Conduct a version scan - Run an nmap version scan targeting the open ports previously identified in the quickscan. The scan will not only attempt to identify running services but also identify services running on non-standard ports. As example, a web server running on tcp port 1000 would be flagged and handled the same as port 80 or 443 in stage 4.

* <b>Stage 4:</b> Targeted service scanning/enumeration - Using the results from the quick scan and version scan, Reckon will begin running more aggressive scanners against the previously identified ports/services. Services are targeted in the following order: HTTP/HTTPS, SMB/NetBIOS/Samba, Other. Please note, in an attempt to prevent inaccurate results, DoS condictions, and general performance issues, Reckon only allows one instance of Nikto to run at a time however will create a scan queue so that Nikto is run against each port (or host) one at a time rather than similtaniously. This same consideration also applies to  dirb scans. 

* <b>Stage 5:</b> Expand Target Scope - After the scans for the top 100 tcp ports have completed, Reckon will begin targeting the remaining tcp ports and proceed through stages 2, 3, and 4 before completing (or moving to the next host if a host list was provided as an argument).
