#!/bin/bash
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

toptcpscan(){ # Conducts a quick scan of top 100 ports.
echo -e "${GREEN}[QS]${NC} Initiating Quick scan of top 100 tcp ports." |tee -a reckon
nmap -Pn -sT $target -oN quickscan --top-ports 100 --open >/dev/null 2>&1;
cat quickscan |grep open |grep -v nmap > .openports
echo -e "${GREEN}[!]${NC} QuickScan identified $(cat quickscan |grep open |grep -v nmap |wc -l) open ports on $target." "\a"  |tee -a reckon
for nports in $(cat quickscan |grep open |grep -v nmap |awk '{print$1}'); do 
	echo "[-]    $nports" |tee -a reckon
done
}

alltcpscan(){ # Scans for all TCP ports. 
echo -e "${GREEN}[FS]${NC} Initiating Full scan for all tcp ports." "\a"  |tee -a reckon
nmap -Pn -sT $target -oN fullscan -p- --open >/dev/null 2>&1;
cat fullscan |grep open |grep -v nmap > .fsopen

for qsopen in $(cat quickscan |grep open |grep -v nmap |awk '{print$1}');do
	cat .fsopen |grep open |grep -v "$qsopen" >> .fsopen1
	mv .fsopen1 .fsopen
done

delta=$(cat .fsopen |wc -l)

if [[ "$delta" -gt "0" ]]; then
	echo -e "${GREEN}[!]${NC} FullScan identified $(cat .fsopen |wc -l) additional ports on $target." "\a"  |tee -a reckon
	for nports in $(cat .fsopen |awk '{print$1}'); do 
		echo "[-]    $nports" |tee -a reckon
	done
	mv .fsopen .openports
	bannerscan
	httpscans
	smbscan
	safescriptscan
else
	echo -e "${GREEN}[!]${NC} FullScan was unable to identify any additional tcp ports."
fi
}

bannerscan(){ # Conduct -sV scan on previously identified open ports
echo -e "${GREEN}[VS]${NC} Initiating Version Scan on $(cat .openports |wc -l) open ports"  |tee -a reckon

for oports in $(cat .openports |grep open |grep -v "\-\-top\-ports" |awk '{print$1}' |awk -F "/" '{print$1}'); do
	nmap -Pn -sT -sV $target -p $oports -oN $oports-version 2> /dev/null 1> /dev/null
	trn=$(cat $oports-version |grep open |awk -F "$(cat $oports-version |grep open |cut -d " " -f1,2,3,4)" '{print$2}' |sed 's/  //g')
	vrn=$(echo $trn |sed 's/  / /g')
	srv=$(cat $oports-version |grep open |awk '{print$3}')

	if [[ -z "$vrn" ]] | [[ "$vrn" == "?" ]]; then
		vrn="Unable to Enumerate Service"
		echo -e "[-]    $oports/tcp is running $srv $vrn"  |tee -a reckon
	else
		echo -e "[-]    $oports/tcp is running $srv via $vrn"  |tee -a reckon
	fi	
done

cat *-version |grep open |grep -v nmap > .openports
}

httpscans(){ # Runs various scanners agaisnt http and https ports
web=$(cat .openports |grep open |grep -v "\-\-top\-ports" |grep http |wc -l)

if [[ "$web" > "0" ]]; then

	for wports in $(cat .openports |grep http |awk '{print$1}' |awk -F "/" '{print$1}' |sort -g); do
		
		if [[ "$wports" == "443" ]]; then
			echo -e "${GREEN}[!]${NC} Enumerating SSL/HTTP on port $wports." |tee -a reckon
			dumpheads
			nmaphttps
			#niktohttps&
			#dirbscan&
		else
			echo -e "${GREEN}[!]${NC} Enumerating HTTP on port $wports." |tee -a reckon
			dumphead
			nmaphttp
			#niktohttp&
			#dirbscan&
		fi	
	done
else
echo -e "${GREEN}[!]${NC} No HTTP Ports Detected " |tee -a reckon
fi
}

nmaphttp(){ # Runs safe NSE scripts for HTTP services

echo -e "${GREEN}[!]${NC} Running NSE Scripts for HTTP on port $wports" |tee -a reckon
nmap -Pn -sT -sV -sC $target -p $wports -oN $wports-enum 2> /dev/null 1> /dev/null
	
	IFS=$'\n'
	for httpenum in $(cat $wports-enum |grep "|" |cut -c 3-); do
		echo "[-]   $httpenum" |tee -a reckon
	done
	unset IFS
}

nmaphttps(){ # Runs safe NSE scripts for HTTPS services

echo -e "${GREEN}[!]${NC} Running NSE Safe Script on tcp port $wports." |tee -a reckon
nmap -Pn -sT -sV -sC $target -p 443 -oN 443-enum 2> /dev/null 1> /dev/null
	
	IFS=$'\n';
	for httpsenum in $(cat $wports-enum |grep "|" |cut -c 3-); do
		echo "[-]   $httpsenum" |tee -a reckon
	done
	unset IFS
}


dumphead(){ # Grabs HTTP headers from http://target/
	IFS=$'\n';
	curl -I http://$target:$wports -D $wports-header 2> /dev/null 1> /dev/null
	hcheck=$(cat $wports-header |grep :)
	
	if [[ -z "$hcheck" ]]; then
		echo "${GREEN}[!]${NC} Unable to dump HTTP Headers." |tee -a reckon
	else
		echo -e "${GREEN}[!]${NC} Dumping HTTP Headers." |tee -a reckon
		for info in $(cat $wports-header |grep ":" |egrep -v "Date:"); do
			echo "[-]   $info" |tee -a reckon
		done
		unset IFS
	fi
}

dumpheads(){  #Grabs HTTP headers from https://target/
	IFS=$'\n';
	curl -I -k https://$target -D $wports-header 2> /dev/null 1> /dev/null
	hcheck=$(cat $wports-header |grep :)
	
	if [[ -z "$hcheck" ]]; then
		echo "${GREEN}[!]${NC} Unable to dump HTTP Headers." |tee -a reckon
	else	
		echo -e "${GREEN}[!]${NC} Dumping HTTP Headers." |tee -a reckon
		for info in $(cat $wports-header |grep ":"); do
			echo "[-]   $info" |tee -a reckon
		done
		unset IFS
	fi
}


niktohttp(){ # Runs one nikto scan at a time against HTTP ports
	
	niktoruns=$(ps -aux |grep nikto |grep $target |wc -l)	
	while [[ "$niktoruns" -gt "0" ]]; do 
		sleep 60 
		niktoruns=$(ps -aux |grep nikto |grep $target |wc -l)
	done 
	
	nikdur=$(pwd)
	echo -e "${GREEN}[!]${NC} Running Nikto on HTTP port $wports" |tee -a reckon
	nikto -h http://$target:$wports 2> /dev/null 1> $wports-nikto
	echo -e "${GREEN}[!]${NC} HTTP/$wports Nikto Scan is ready for review: $nikdur/$wports-nikto" "\a" |tee -a reckon
}

niktohttps(){ # Runs one nikto scan at a time against HTTPS ports
	
	niktoruns=$(ps -aux |grep nikto |grep $target |wc -l)	
	while [[ "$niktoruns" -gt "0" ]]; do 
		sleep 60 
		niktoruns=$(ps -aux |grep nikto |grep $target |wc -l)
	done 	

	nikdur=$(pwd)
	echo -e "${GREEN}[!]${NC} Running Nikto on HTTP port $wports" |tee -a reckon
	nikto -h https://$target 2> /dev/null 1> $wports-nikto
	echo -e "${GREEN}[!]${NC} HTTP/$wports Nikto Scan is ready for review: $nikdur/$wports-nikto" "\a" |tee -a reckon
}

smbvulnscan(){ # Runs all smb-vuln NSE scripts. DANGER: This could crash the target.
	echo -e "${GREEN}[!]${NC} Running NSE Vuln Scripts for SMB - Target might crash!" |tee -a reckon
	nmap -p 137,139,445 $target --script smb-vuln* -oN nse-smbscan 2> /dev/null 1> /dev/null
	
	smbresults=$(cat nse-smbscan |grep "|" |wc -l)
	
	if [[ "$smbresults" -gt "0" ]]; then
		IFS=$'\n';
		for smbscan in $(cat nse-smbscan |grep "|" |cut -c 3-); do
			echo "[-]   $smbscan" |tee -a reckon
		done
		unset IFS
	else 
	echo -e "${GREEN}[!]${NC} NSE Scripts for SMB Failed. No Results." |tee -a reckon
	fi
}

enlnx(){ # Runs enum for linux 
	enumdir=$(pwd)
	echo -e "${GREEN}[!]${NC} Running Enum4Linux on TCP/NetBios ports." |tee -a reckon
	enum4linux $target 1> smb-en4lnx 2> /dev/null
	echo -e "${GREEN}[!]${NC} Enum4Linux Report is ready for review: $enumdir/smb-en4lnx" "\a"	 |tee -a reckon
}

smbsafense(){ # Runs safe NSE SMB scripts
echo "${GREEN}[!]${NC} Running NSE Safe Scripts for SMB " |tee -a reckon
nmap -Pn -sT -sV -sC $target -p 137,139,445  -oN smb-safeenum 2> /dev/null 1> /dev/null
	
	IFS=$'\n'
	for smbenumsafe in $(cat smb-safeenum |grep "|" |cut -c 3-); do
		echo "[-]   $smbenumsafe"
	done
	unset IFS
}

smbscan(){ # Checks quick scan results for SMB, and NetBios ports, then runs SMB enum functions
smbcnt=$(cat .openports |grep open |grep -v "\-\-top\-ports" |egrep -i '(microsoft-ds|netbios-ssn|samba)'|wc -l)

if [[ "$smbcnt" > "0" ]]; then
echo -e "${GREEN}[SE]${NC} Initiating SMB Enumeration" |tee -a reckon
	enlnx
	smbsafense
	#smbvulnscan
#else
#	echo "${GREEN}[!]${NC} No SMB Ports Detected" |tee -a reckon
fi
}

safescriptscan(){ # Runs safe NSE scripts all services not HTTP or SMB/NetBIOS
for otherports in $(cat .openports |egrep -v '(http|data bytes|microsoft-ds|netbios-ssn|samba)' |awk -F "/" '{print$1}'); do
	echo -e "${GREEN}[!]${NC} Running NSE Safe Script on tcp port $otherports." |tee -a reckon
	nmap -Pn -sT -sV -sC $target -p $otherports -oN $otherports-enum 2> /dev/null 1> /dev/null

	results=$(cat $otherports-enum |grep "|" |wc -l)


	if [[ "$results" -gt "0" ]]; then

	IFS=$'\n'
	for nports in $(cat $otherports-enum |grep "|" |cut -c 3-); do
		echo "[-]   $nports" |tee -a reckon
	done
	unset IFS

	else
		echo "[-]   No results from NSE safe script." |tee -a reckon
	fi 
done
}

pendscans(){ # Prevents multiple instances of Nikto from running. Creates a queue for multiple scans.
	niktoruns=$(ps -aux |grep nikto |grep $target 2> /dev/null |wc -l)	
	
	if [[ "$niktoruns" -gt "0" ]]; then
	echo -e "${GREEN}[!]${NC} Added $target to Nikto scan queue" |tee -a reckon
	
		while [[ "$niktoruns" -gt "0" ]]; do 
			sleep 60
			niktoruns=$(ps -aux |grep nikto |grep $target 2> /dev/null |wc -l)	
		done 
	fi
}

singlehost(){ # Runs enumeration functions for a single host $1 user arguement.
workdir=$(pwd)
mkdir $workdir/$target 2> /dev/null
cd $workdir/$target

toptcpscan
bannerscan
httpscans
smbscan
echo -e "${GREEN}[SC]${NC} Initiating NSE Safe Script scans" |tee -a reckon
safescriptscan
#alltcpscan
#pendscans
echo -e "${GREEN}[!]${NC} Reckon enumeration is complete" "\a" "\a" |tee -a reckon
cd $workdir
}

multihost(){ # Runs enumeration functions for user provided list in $1 argument.	
workdir=$(pwd)
mkdir $workdir/$target 2> /dev/null
cd $workdir/$target
		
#toptcpscan
#bannerscan
#httpscans
#smbscan
#safescriptscan
#alltcpscan
#bannerscan
#safescriptscan
#pendscans
cd $workdir
}

splash(){ # Banner just because.
echo -e "${GREEN} ---------------------------------${NC}"
echo -e "${GREEN} |  _ \ ___  ___| | _____  _ __   ${NC}"
echo -e "${GREEN} | |_) / _ \/ __| |/ / _ \| '_ \  ${NC}"
echo -e "${GREEN} |  _ <  __/ (__|   < (_) | | | | ${NC}"
echo -e "${GREEN} |_| \_\___|\___|_|\_\___/|_| |_| ${NC}"
echo -e "${GREEN} ---------------------------------${NC}"
echo -e "${GREEN} --- Written by MaliceInChains ---${NC}"
echo -e ""
}

usage(){
		echo -e "[!] Example Usage: "
		echo -e "[-] ./reckon.sh 192.168.1.100 "
		echo -e "[-] ./reckon.sh scanme.nmap.org"
		echo -e "[-] ./reckon.sh /home/user/hostlist.txt "
		echo ""
}

validate(){ # Validates $1 user argument and determines single host, or host file.
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
	singlehost $target

elif [[ "$hostlist" -gt "0" ]];then
filecheck=$(file $userinput |grep "ASCII text" |wc -l)

	if [[ "$filecheck" -gt "0" ]]; then
		listcnt=$(cat $userinput |wc -l)	
		echo -e "${GREEN}[RK]${NC} Enumerating $listcnt total hosts."
			for target in $(cat $userinput); do 
				testinput=$(ping -w1 $target 2>&1)
				hostlisttarget=$(echo $testinput |grep "bytes of data" |wc -l)

					if [[ "$hostlisttarget" -gt "0" ]];then
						multihost $target $userinput
					else 
						echo "$target not a valid host"
					fi
			done
	else 
		echo ""
		echo -e "${RED}[ER] Input Error: $1 is not a valid IP, domain, or list file. ${NC}"
		echo ""
		usage
	fi
fi
}
splash
validate $*