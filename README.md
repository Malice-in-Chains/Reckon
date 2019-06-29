# Reckon
Is a simple wrapper script written in bash. It was written in preparation for the OSCP exam to help me be more time efficient during testing by automating some basic tasks and scans with a focus on enumerating the more targetable services like HTTP and SMB.

### Prerequisites
Reckon will run on any Kali Linux image (2017 and above) and is currently wrapping multiple tools and scripts such as: Nmap, Nmap-NSE, Curl, Enum4linux, Nikto, and Dirb. Reckon shouldn't have issue running on other Linux distros provided these tools are present.

### Example Usage
``` ./reckon.sh 10.10.10.10 ```

``` ./reckon.sh scanme.nmap.org```

``` ./reckon.sh /home/user/hostlist.txt```

### Workflow
Reckon's work flow was designed to provide incremental results so you an progress through manual enumeration while waiting on results from longer scans such as Nikto or Dirb. Again, the intent of this wrapper is to increase time efficiency by minimize waiting/downtime. 

### Reckon runs in five stages

* <b>Stage 1:</b> Directory Creation - Upon execution, a target directory will be created in the current working directory. The results of scans will be filtered, organized, and printed to terminal while copies of the scans results will be stored in the current working directory. This stage takes less than a second to complete.

* <b>Stage 2:</b> QuickScan - Using nmap --top-port arugement to scan for the top 100 common tcp ports. This number can be changed by modifying the tports variable (line 5). The purpose of this scan is to give quick (non-verbose) results so the tester can immediately begin prioritizing where to focus manual efforts. This stage usually completes in 10 seconds or less.

* <b>Stage 3:</b> VersionScan - Run an nmap version scan (sV) targeting the open ports previously identified in the quickscan. The scan will not only attempt to identify running services but also identify services running on non-standard ports. As example, a web server running on tcp port 25 would be flagged and addressed the same as port 80 or 443 in next stages.

* <b>Stage 4:</b> EnumerationScan - Reckon will begin running NSE Default scripts followed by more aggressive scans/scripts such as NSE Vuln Scripts, Nikto, and Dirb against the previously identified ports/services when/where appropriate. Services are currently prioritized by HTTP, SMB, Other respectively. Identified HTTP and SMB services are given more time and attention than "Others". It's also important to note that in attempt to prevent inaccurate results, DoS conditions, and general performance issues, Reckon only allows one instance of Nikto (or Dirb) to run at a time but will create queue if Reckon is being run against a hostlist or a single target has multiple HTTP services running. 

* <b>Stage 5:</b> FullScan - At this point only the top 100 tcp and udp ports have been identified and scanned. In this stage, Reckon will begin scanning the remaining 65435 (65535 - 100) tcp and udp ports. Previously identified ports will not be rescanned however any newly identified open ports will be sent through Stages 3 and 4. This phase is really for peace of mind for the event that a target server is running obscure services on epimeral ports. 

### Limitations
* Reckon is only a simple bash script running mostly default scans for the scripts/tools it is wrapping. It should not be considered "Aggressive Enumeration" by any means and should not replace manual enumeration. This script is intended to automate and provide results to simplistic/common tasks during the enumeration phase.

* Reckon adhears to all OSCP exam restrictions: https://support.offensive-security.com/#!oscp-exam-guide.md
