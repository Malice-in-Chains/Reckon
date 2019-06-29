#!/bin/bash
# Written by MaliceInChains - maliceinchains106@gmail.com 
# -----------------------------------------------------------------
# Reckon performs common active reconnaissance tasks in order speed 
# up scanning and enumeration processes during penetration testing.
# -----------------------------------------------------------------

# Adjust the number of --top-ports for Phase 2 Quick Scan
tports=100

# Color Variables
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# For calculating run time
SECONDS=0

topscan(){ # Conducts a quick scan of top ___ TCP ports, change tports for top 10
	nmap -Pn -sT $target -oN quickscan --top-ports $tports --open >/dev/null 2>&1;
	cat quickscan |grep open |grep -v nmap > .openports
	echo -e "${GREEN}[!]${NC}   Nmap identified $(cat quickscan |grep open |grep -v nmap |wc -l) open TCP ports on $target" "\a"  |tee -a reckon
	
	for nports in $(cat quickscan |grep open |grep -v nmap |awk '{print$1}'); do 
		echo "[-]      $nports" |tee -a reckon
	done

	# Conducts a quick scan of top 100 UDP ports.
	nmap -Pn -sU $target -oN quickudpscan --top-ports $tports --open >/dev/null 2>&1;
	cat quickudpscan |grep open |grep -v filtered |grep -v nmap > .openudpports
	echo -e "${GREEN}[!]${NC}   Nmap identified $(cat quickudpscan |grep open |grep -v filtered |grep -v nmap |wc -l) open UDP ports on $target" "\a"  |tee -a reckon
	
	for nports in $(cat quickudpscan |grep open |grep -v filtered |grep -v nmap |awk '{print$1}'); do 
		echo "[-]      $nports" |tee -a reckon
	done
}

versionscantcp(){ # Conduct -sV scan on previously identified TCP ports

	for oports in $(cat .openports |grep open |grep -v "\-\-top\-ports" |awk '{print$1}' |awk -F "/" '{print$1}'); do
		nmap -Pn -sT -sV $target -p $oports -oN $oports-version 2> /dev/null 1> /dev/null
		trn=$(cat $oports-version |grep open |awk -F "$(cat $oports-version |grep open |cut -d " " -f1,2,3,4)" '{print$2}' |sed 's/  //g')
		vrn=$(echo $trn |sed 's/  / /g')
		srv=$(cat $oports-version |grep open |awk '{print$3}')

		if [[ -z "$vrn" ]] | [[ "$vrn" == "?" ]]; then
			vrn="- Nmap was unable to identify the service or version"
			echo -e "[-]      $oports/TCP may be running $srv $vrn"  |tee -a reckon
		else
			echo -e "[-]      $oports/TCP is running $srv service via $vrn"  |tee -a reckon
		fi	
	done
}

versionscanudp(){ # Conduct -sV scan on previously identified UDP ports

	for oports in $(cat .openudpports |grep open |grep -v filtered |awk '{print$1}' |awk -F "/" '{print$1}'); do
		nmap -Pn -sU -sV $target -p $oports -oN $oports-udp-version 2> /dev/null 1> /dev/null
		trn=$(cat $oports-udp-version |grep open |awk -F "$(cat $oports-udp-version |grep open |cut -d " " -f1,2,3,4)" '{print$2}' |sed 's/  //g')
		vrn=$(echo $trn |sed 's/  / /g')
		srv=$(cat $oports-udp-version |grep open |awk '{print$3}')

		if [[ -z "$vrn" ]] | [[ "$vrn" == "?" ]]; then
			vrn="- Nmap was unable to identify the service or version"
			echo -e "[-]      $oports/UDP may be running $srv $vrn"  |tee -a reckon
		else
			echo -e "[-]      $oports/UDP is running $srv service via $vrn"  |tee -a reckon
		fi	
	done
}

httpenum(){ # Runs various scanners against http and https ports
	
	for wports in $(cat .openports |grep http |grep -v "Microsoft Windows RPC over HTTP" |awk '{print$1}' |awk -F "/" '{print$1}' |sort -g); do
		pullheaders
		nsedefhttp
	done
	niktohttp&
	dirbhttp&
}

pullheaders(){ # Grabs HTTP headers from http://target/
	IFS=$'\n';
	if [[ $wports == "443" ]]; then
		curl -I -k https://$target -D $wports-header 2> /dev/null 1> /dev/null
	else
		curl -I http://$target:$wports -D $wports-header 2> /dev/null 1> /dev/null
	fi
	
	hcheck=$(cat $wports-header |grep :)
	if [[ -z "$hcheck" ]]; then
		echo -e "${GREEN}[!]${NC} Unable to pull HTTP headers for port $wports." |tee -a reckon
	else
		echo -e "${GREEN}[!]${NC}    Pulling HTTP headers for port $wports." |tee -a reckon
			for info in $(cat $wports-header |grep ":" |egrep -v "Date:"); do
				echo "[-]      $info" |tee -a reckon
			done
	fi
	unset IFS
}

niktohttp(){ # Runs default Nikto scan
	wports=$(cat .openports |grep http |grep -v "Microsoft Windows RPC over HTTP" |wc -l)
	if [[ "$wports" -gt "0" ]];then
		echo -e "${GREEN}[!]${NC}    Nikto queued for http ports." |tee -a reckon
		for nikports in $(cat .openports |grep http |grep -v "Microsoft Windows RPC over HTTP" |awk '{print$1}' |awk -F "/" '{print$1}' |sort -g); do
		
			if [[ "$wports" == "443" ]]; then
				nikto -h https://$target  2> /dev/null 1> $nikports-nikto
				echo -e "${GREEN}[!]${NC} The Nikto scan for https://$target has completed." "\a" |tee -a reckon
			else
				nikto -h http://$target:$nikports 2> /dev/null 1> $nikports-nikto
				echo -e "${GREEN}[!]${NC} The Nikto scan for http://$target:$nikports has completed." "\a" |tee -a reckon
			fi

			IFS=$'\n';
			for info in $(cat $nikports-nikto |grep + |egrep -v '(Target IP:|Target Hostname:|Target Port:|Start Time:|End Time:|host\(s\) tested|reported on remote host)' |sed 's/+ //g'); do
			echo "[-]      $info" |tee -a reckon
			done
			unset IFS
		done
	fi
}

dirbhttp(){  #Runs dirb against / of web services
	wports=$(cat .openports |grep http |grep -v "Microsoft Windows RPC over HTTP" |wc -l)
	if [[ "$wports" -gt "0" ]];then
		echo -e "${GREEN}[!]${NC}    Dirb queued for http ports." |tee -a reckon
		for dirbports in $(cat .openports |grep http |grep -v "Microsoft Windows RPC over HTTP" |awk '{print$1}' |awk -F "/" '{print$1}' |sort -g); do
		
			if [[ "$wports" == "443" ]]; then
				dirb https://$target/ /usr/share/wordlists/dirb/big.txt -S -r -w  2> /dev/null 1> $dirbports-dirb
				echo -e "${GREEN}[!]${NC} The Dirb scan for https://$target/ has completed." "\a" |tee -a reckon
			else
				dirb http://$target:$dirbports/ /usr/share/wordlists/dirb/big.txt -S -r -w 2> /dev/null 1> $dirbports-dirb
				echo -e "${GREEN}[!]${NC} The Dirb scan for http://$target:$dirbports/ has completed." "\a" |tee -a reckon
			fi

			dirbcheck=$(cat $dirbports-dirb |tr "\015" "\n" |egrep '(==>|\+)' |sed 's/+ http/http/g' |sed 's/==> //g' |grep -v Testing:|wc -l)
			if [[ "$dirbcheck" -gt "0" ]]; then
				IFS=$'\n';
					for info in $(cat $dirbports-dirb |tr "\015" "\n" |egrep '(==>|\+)' |sed 's/+ http/http/g' |sed 's/==> //g' |grep -v Testing:); do
					echo "[-]      $info" |tee -a reckon
					done
				unset IFS
			else
				if [[ "$wports" == "443" ]]; then
					echo -e "${GREEN}[!]${NC} Dirb found no file or directories in https://$target/ " "\a" |tee -a reckon
				else
					echo -e "${GREEN}[!]${NC} Dirb found no file or directories in http://$target:$dirbports/ " "\a" |tee -a reckon
				fi
			fi
		done
	fi
}

nsedefhttp(){ # Runs Default HTTP NSE scripts
	echo -e "${GREEN}[!]${NC} Running NSE Default Scripts against HTTP on port $wports" |tee -a reckon
	nmap -Pn -sT -sV -sC $target -p $wports -oN $wports-nse 2> /dev/null 1> /dev/null
	results=$(cat $wports-nse |grep "|" |wc -l)

	if [[ "$results" -gt "0" ]]; then
		IFS=$'\n';
		for nsescript in $(cat $wports-nse |grep "|" |cut -c 3-); do
			echo "[-]      $nsescript" |tee -a reckon
		done
		unset IFS
	else
		echo "[-]      No results from NSE Default Scripts" |tee -a reckon
	fi
}

nsedefother(){ # Runs Default NSE scripts
	
	openudpports=$(cat .openudpports |grep open |egrep -vi '(microsoft-ds|netbios-ssn|samba|http)' |grep -v filtered |wc -l)
	opentcpports=$(cat .openports |egrep -vi '(microsoft-ds|netbios-ssn|samba|smb|http)' |grep open |wc -l)
	
	# NSE Default scripts for open TCP ports
	if [[ "$opentcpports" -gt "0" ]]; then
		for otherports in $(cat .openports |egrep -vi '(microsoft-ds|netbios-ssn|samba|smb|http)' |grep open |awk -F "/" '{print$1}'); do
			echo -e "${GREEN}[!]${NC} Running NSE Default Scripts against TCP port $otherports" |tee -a reckon
			nmap -Pn -sT -sV -sC $target -p $otherports --open -oN $otherports-tcp-nse 2> /dev/null 1> /dev/null
			results=$(cat $otherports-tcp-nse |grep "|" |wc -l)

			if [[ "$results" -gt "0" ]]; then
				IFS=$'\n';
				for nsescript in $(cat $otherports-tcp-nse |grep "|" |cut -c 3-); do
					echo "[-]      $nsescript" |tee -a reckon
				done
				unset IFS
			fi
		done
	fi
	echo "" > .openports

	# NSE Default scripts for open UDP ports
	if [[ "$openudpports" -gt "0" ]]; then
		for otherports in $(cat .openudpports |egrep -vi '(microsoft-ds|netbios-ssn|samba|http)' |grep open |awk -F "/" '{print$1}'); do
			echo -e "${GREEN}[!]${NC} Running NSE Default Scripts against UDP port $otherports" |tee -a reckon
			nmap -Pn -sU -sV -sC $target -p $otherports --open -oN $otherports-udp-nse 2> /dev/null 1> /dev/null
			results=$(cat $otherports-udp-nse |grep "|" |wc -l)

			if [[ "$results" -gt "0" ]]; then
				IFS=$'\n';
				for nsescript in $(cat $otherports-udp-nse |grep "|" |cut -c 3-); do
					echo "[-]      $nsescript" |tee -a reckon
				done
				unset IFS
			fi
		done
	fi	
	echo "" > .openudpports
}

enumflnx(){ # Runs enum4linux
	enumdir=$(pwd)
	echo -e "${GREEN}[!]${NC} Running Enum4Linux on $target" |tee -a reckon
	enum4linux $target 1> smb-enum4linux 2> /dev/null
	smblines=$(cat $enumdir/smb-enum4linux |wc -l)
	echo -e "${GREEN}[!]${NC} Enum4Linux Report contains $smblines lines! "  |tee -a reckon
	echo -e "${GREEN}[!]${NC} Review: $enumdir/smb-enum4linux" |tee -a reckon

	IFS=$'\n'
	for eflrep in $(cat smb-enum4linux |egrep '(allows sessions|\/\/)' |sed 's/\[+] //g' |grep -v "enum4linux v"); do
	echo "[-]      $eflrep" |tee -a reckon
	done
	unset IFS
}

smbnsedefault(){ # Runs Def NSE SMB scripts
	echo -e "${GREEN}[!]${NC} Running NSE Default Scripts for SMB ports" |tee -a reckon
	for smbports in $(cat .open* |grep open |egrep -i '(microsoft-ds|netbios-ssn|samba|smb)'|awk -F "/" '{print$1}' |sort -g);do
		nmap -Pn -sV -sC -sT -sU $target -p $smbports --open -oN $smbports-smb-nsedef 2> /dev/null 1> /dev/null
		IFS=$'\n'
			for smbenumdef in $(cat $smbports-smb-nsedef |grep "|" |cut -c 3-); do
				echo "[-]      $smbenumdef" |tee -a reckon
			done
			unset IFS
	done
}

smbnsevulns(){ # Runs all smb-vuln NSE scripts. DANGER: This could crash the target
	echo -e "${GREEN}[!]${NC} Running NSE Vuln Scripts for SMB" |tee -a reckon
	nmap -sT -sU -sV -p 137,138,139,445 $target --script smb-vuln* -oN smb-nsevulns 2> /dev/null 1> /dev/null
	
	smbresults=$(cat smb-nsevulns |grep "|" |wc -l)
	
	if [[ "$smbresults" -gt "0" ]]; then
		IFS=$'\n';
		for smbscan in $(cat smb-nsevulns |grep "|" |cut -c 3-); do
			echo "[-]      $smbscan" |tee -a reckon
		done
		unset IFS
	else 
	echo -e "${GREEN}[!]${NC} NSE Vuln Scripts for SMB - No Results" |tee -a reckon
	fi
}

enumscans(){ # Creates a priority of services to enumerate first
	wports=$(cat .openports |grep http |wc -l)
		if [[ "$wports" -gt "0" ]]; then
			httpenum
		fi

	smbports=$(cat .open* |egrep -i '(microsoft-ds|netbios-ssn|samba|smb)'|wc -l)
		if [[ "$smbports" -gt "0" ]]; then
			enumflnx
			smbnsedefault
			smbnsevulns
		fi

	otherports=$(cat .open* |egrep -vi '(microsoft-ds|netbios-ssn|samba|http)' |wc -l)
		if [[ "$otherports" -gt "0" ]]; then
				nsedefother
		fi
}

alltcpscan(){ # Scans for all TCP ports but excludes previously discovered ports in output
	nmap -Pn -sT $target -oN fullscan -p- --open >/dev/null 2>&1;
	cat fullscan |grep open |grep -v nmap > .fsopen

	for qsopen in $(cat quickscan |grep open |grep -v nmap |awk '{print$1}');do
		cat .fsopen |grep open |grep -v "$qsopen" >> .fsopen1
		mv .fsopen1 .fsopen
	done

	delta=$(cat .fsopen |wc -l)

	if [[ "$delta" -gt "0" ]]; then
		echo -e "${GREEN}[!]${NC}   Full Scan identified $(cat .fsopen |wc -l) additional TCP port(s) on $target" "\a"  |tee -a reckon
		for nports in $(cat .fsopen |awk '{print$1}'); do 
			echo "[-]      $nports" |tee -a reckon
		done
		mv .fsopen .openports

		echo -e "${GREEN}[!]${NC} Running Version Scan against open port(s)"  |tee -a reckon
		versionscantcp
	
		echo -e "${GREEN}[!]${NC} Running Enumeration Scans against $(cat .openports |wc -l) open port(s)" |tee -a reckon
		enumscans
	else
		echo -e "${GREEN}[!]${NC}   No additional TCP ports identified" |tee -a reckon
	fi
}

alludpscan(){ # Scans for all UDP ports but excludes previously discovered ports in output
	nmap -Pn -sU $target -oN fulludpscan -p- --open >/dev/null 2>&1;
	cat fulludpscan |grep open |grep -v filtered |grep -v nmap > .fsopen

	for qsopen in $(cat quickudpscan |grep open |grep -v filtered |grep -v nmap |awk '{print$1}');do
		cat .fsopen |grep open |grep -v "$qsopen" >> .fsopen1
		mv .fsopen1 .fsopen
	done

	delta=$(cat .fsopen |wc -l)

	if [[ "$delta" -gt "0" ]]; then
		echo -e "${GREEN}[!]${NC}   Full Scan identified $(cat .fsopen |wc -l) additional UDP port(s) on $target" "\a"  |tee -a reckon
		for nports in $(cat .fsopen |awk '{print$1}'); do 
			echo "[-]      $nports" |tee -a reckon
		done
		mv .fsopen .openudpports

		echo -e "${GREEN}[!]${NC} Running Version Scan against $(cat .openudpports |wc -l) UDP port(s)"  |tee -a reckon
		versionscanudp
	
		echo -e "${GREEN}[!]${NC} Running Enumeration Scans against $(cat .openudpports |wc -l) UDP ports(s)" |tee -a reckon
		enumscans
	else
		echo -e "${GREEN}[!]${NC}   No additional UDP ports identified" |tee -a reckon
	fi
}

waitforscans(){ # Holds the terminal open until all Nikto scans have completed
    scansrunning=$(ps -aux |grep $target |grep -v grep |grep -v reckon |wc -l)
	echo -e "${GREEN}[!]${NC} Waiting on $scansrunning scan(s) to complete"
	if [[ "$scansrunning" -gt "0" ]]; then
		while [[ "$scansrunning" -gt "0" ]]; do 
			sleep 1
			scansrunning=$(ps -aux |grep $target |grep -v grep |grep -v reckon |wc -l)	
		done 
	fi
}

mainfunction(){ # Runs enumeration functions for a single host $1 user arguement
	workdir=$(pwd)
	mkdir $workdir/$target 2> /dev/null
	cd $workdir/$target
	echo -e "${GREEN}[!]${NC} Testing directory created at: $(pwd) " |tee -a reckon

	echo -e "${GREEN}[!]${NC} Running Quick Scan against the top $tports TCP/UDP ports" |tee -a reckon
	topscan

	openports=$(cat .open* |wc -l)
	if [[ "$openports" -gt "0" ]]; then
	echo -e "${GREEN}[!]${NC} Running Version Scans against open ports"  |tee -a reckon
	fi

	tcpports=$(cat .openports |wc -l)
	if [[ "$tcpports" -gt "0" ]]; then	
	versionscantcp
	fi

	udpports=$(cat .openudpports |wc -l)
	if [[ "$udpports" -gt "0" ]]; then
	versionscanudp
	fi

	if [[ "$tcpports" -gt "0" ]]; then
	echo -e "${GREEN}[!]${NC} Running Enumeration Scripts against identified TCP ports" |tee -a reckon
	enumscans
	fi

	echo -e "${GREEN}[!]${NC} Running Full Scan against all TCP ports" |tee -a reckon
	alltcpscan
	

	# Enabling this will do a full UDP scan, which will take a significant amount of time.
	# echo -e "${GREEN}[!]${NC} Running Full Scan against all UDP ports. Get comfortable, this may take awhile.." |tee -a reckon
	# alludpscan

	scansrunning=$(ps -aux |grep $target |grep -v grep |grep -v reckon |wc -l)
	if [[ "$scansrunning" -gt "0" ]]; then	
	waitforscans
	fi

	rm .openports
	rm .openudpports
	echo -e "${GREEN}[!]${NC} -------- Reckon Scan Complete -------- " |tee -a reckon
	echo -e "${GREEN}[!]${NC} $(($SECONDS / 3600)) hours, $((($SECONDS / 60) % 60)) minutes, and $(($SECONDS % 60)) seconds" |tee -a reckon
	echo -e "${GREEN}[!]${NC} -------------------------------------- " 
	echo -e "${GREEN}[!]${NC} The following files have been created: "
	ls |sort -n > .files
	for files in $(cat .files); do
		echo "[-]      $files"
	done
	echo -e "${GREEN}[!]${NC} -------------------------------------- " 
}

splash(){ # Banner just because
	echo -e "${GREEN} ---------------------------------${NC}"
	echo -e "${GREEN} |  _ \ ___  ___| | _____  _ __   ${NC}"
	echo -e "${GREEN} | |_) / _ \/ __| |/ / _ \| '_ \  ${NC}"
	echo -e "${GREEN} |  _ <  __/ (__|   < (_) | | | | ${NC}"
	echo -e "${GREEN} |_| \_\___|\___|_|\_\___/|_| |_| ${NC}"
	echo -e "${GREEN} ---------------------------------${NC}"
	echo -e "${GREEN} --- Written by MaliceInChains ---${NC}"
	echo -e ""
}

usage(){ # To be printed when user input is not valid
		echo -e "All scan results will be stored in the current working directory"
		echo -e ""
		echo -e "[!] Example Usage: "
		echo -e "[-] ./reckon.sh 192.168.1.100 "
		echo -e "[-] ./reckon.sh scanme.nmap.org"
		echo -e "[-] ./reckon.sh /home/malice/hostlist.txt "
		echo ""
}

validate(){ # Validates $1 user argument and determines single host, or host file
	userinput=$1
	testinput=$(ping -w1 $userinput 2>&1)
	singlehost=$(echo $testinput |egrep '(bytes of data|data bytes)' |wc -l)
	hostlist=$(echo $testinput |grep "Name or service not known" |wc -l)

	if [[ -z "$userinput" ]]; then
		echo ""
		usage
		exit 1
	fi

	if [[ "$singlehost" -gt "0" ]];then
		target=$userinput
		mainfunction $target

	elif [[ "$hostlist" -gt "0" ]];then
		filecheck=$(file $userinput |grep "ASCII text" |wc -l)

		if [[ "$filecheck" -gt "0" ]]; then
			listcnt=$(cat $userinput |wc -l)	
				echo -e "${GREEN}[!]${NC} Host list detected. Scanning $listcnt total hosts" 
				for target in $(cat $userinput); do 
					testinput=$(ping -w1 $target 2>&1)
					hostlisttarget=$(echo $testinput |grep "bytes of data" |wc -l)

						if [[ "$hostlisttarget" -gt "0" ]];then
							mainfunction $target $userinput
						else 
							echo -e "${RED}[ER] Host list error: $1 is not a valid IP or domain ${NC}"
						fi
				done
		else 
			echo ""
			echo -e "${RED}[ER]  Error: $1 is not a valid IP, domain, or host list ${NC}"
			echo ""
			usage
		fi
	fi
}

splash
validate $*
