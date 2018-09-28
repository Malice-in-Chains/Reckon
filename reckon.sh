#!/bin/bash
GREEN='\033[0;32m'
NC='\033[0m'
tports=100

# Quick Scan of top 10000 Ports
toptcpscan(){
echo -e "${GREEN}[QS] Initiating Stage 1: Quick Scan (Top $tports TCP Ports) ${NC}" |tee -a reckon
nmap -Pn -sT $target -oN quickscan --top-ports $tports --open >/dev/null 2>&1;
echo -e "[*] QuickScan identified $(cat quickscan |grep open |grep -v "\-\-top\-ports" |wc -l) open ports on $target." "\a"  |tee -a reckon
for nports in $(cat quickscan |grep open |grep -v "\-\-top\-ports" |awk '{print$1}'); do 
	echo "[-]  " $nports |tee -a reckon
done
}

alltcpscan(){
echo -e "${GREEN}[QS] Initiating Stage 9: Full TCP Scan ${NC}" |tee -a reckon
nmap -Pn -sT $target -oN fullscan -p- --open >/dev/null 2>&1;
echo -e "[*] QuickScan identified $(cat quickscan |grep open |grep -v "\-\-top\-ports" |wc -l) open ports on $target." "\a"  |tee -a reckon
for nports in $(cat quickscan |grep open |grep -v "\-\-top\-ports" |awk '{print$1}'); do 
	echo "[-]  " $nports |tee -a reckon
done
}

bannerscan(){
echo -e "${GREEN}[VS] Initiating Stage 2: Version Scan ${NC}"  |tee -a reckon

for oports in $(cat quickscan |grep open |grep -v "\-\-top\-ports" |awk '{print$1}' |awk -F "/" '{print$1}'); do
	nmap -Pn -sT -sV $target -p $oports -oN $oports-version 2> /dev/null 1> /dev/null
	vrn=$(cat $oports-version |grep open |awk -F "$(cat $oports-version |grep open |cut -d " " -f1,2,3,4)" '{print$2}' |sed 's/  //g')
	srv=$(cat $oports-version |grep open |awk '{print$3}')

	if [[ -z "$vrn" ]] | [[ "$vrn" == "?" ]]; then
		vrn="Unable to Enumerate Service"
		echo -e "[-]   $oports/tcp is running $srv $vrn"  |tee -a reckon
	else
		echo -e "[-]   $oports/tcp is running $srv via $vrn"  |tee -a reckon
	fi	
done
}

httpscans(){ 
web=$(cat quickscan |grep open |grep -v "\-\-top\-ports" |grep http |awk '{print$1}' |wc -l)

if [[ "$web" > "0" ]]; then
echo -e "${GREEN}[WS] Initiating Stage 3: HTTP(S) Enumeration ${NC}" |tee -a reckon

	for wports in $(cat quickscan |grep open |grep -v "\-\-top\-ports" |grep http |awk '{print$1}' |awk -F "/" '{print$1}'); do
		
		if [[ "$wports" == "443" ]]; then
			echo -e "[-] Enumerating TLS/SSL HTTP Services." |tee -a reckon
			dumpheads
			nmaphttps
			niktohttps&
		else
			echo -e "${GREEN}[-] Enumerating HTTP Services. ${NC}" |tee -a reckon
			dumphead
			nmaphttp
			niktohttp&
		fi	
	done
else
echo -e "[*] No HTTP Ports Detected " |tee -a reckon
fi
}


# Subfunction of targetscan
nmaphttp(){

echo "[*] Running NSE Scripts for HTTP on port $wports" |tee -a reckon
nmap -Pn -sT -sV -sC $target -p $wports -oN $wports-enum 2> /dev/null 1> /dev/null
	
	IFS=$'\n'
	for httpenum in $(cat $wports-enum |grep "|" |cut -c 3-); do
		echo "[-]   $httpenum" |tee -a reckon
	done
	unset IFS
}
# Subfunction of targetscan for ssl/tls sites
nmaphttps(){

echo "[*] Running NSE Scripts for HTTPS on port $wports" |tee -a reckon
nmap -Pn -sT -sV -sC $target -p 443 -oN 443-enum 2> /dev/null 1> /dev/null
	
	IFS=$'\n';
	for httpsenum in $(cat $wports-enum |grep "|" |cut -c 3-); do
		echo "[-]   $httpsenum" |tee -a reckon
	done
	unset IFS
}

# Subfunction of targetscan
dumphead(){
	IFS=$'\n';
	curl -I http://$target:$wports -D $wports-header 2> /dev/null 1> /dev/null
	hcheck=$(cat $wports-header |grep :)
	
	if [[ -z "$hcheck" ]]; then
		echo "[*] Unable to dump HTTP Headers on port $wports" |tee -a reckon
	else
		echo -e "[*] Dumping HTTP Headers for HTTP on port $wports" |tee -a reckon
		for info in $(cat $wports-header |grep ":" |egrep -v "Date:"); do
			echo "[-]   $info" |tee -a reckon
		done
		unset IFS
	fi
}

# Subfunction of targetscan for ssl/tls sites
dumpheads(){
	IFS=$'\n';
	curl -I -k https://$target -D $wports-header 2> /dev/null 1> /dev/null
	hcheck=$(cat $wports-header |grep :)
	
	if [[ -z "$hcheck" ]]; then
		echo "[*] Unable to dump HTTP Headers on port $wports" |tee -a reckon
	else	
		echo -e "[*] Dumping HTTP Headers on port $wports" |tee -a reckon
		for info in $(cat $wports-header |grep ":"); do
			echo "[-]   $info" |tee -a reckon
		done
		unset IFS
	fi
}

# Subfunction of targetscan
niktohttp(){
	
	niktoruns=$(ps -aux |grep nikto |grep $target |wc -l)	
	while [[ "$niktoruns" -gt "0" ]]; do 
		sleep 60 
		niktoruns=$(ps -aux |grep nikto |grep $target |wc -l)
	done 
	
	nikdur=$(pwd)
	echo -e "[*] Running Nikto on HTTP port $wports" |tee -a reckon
	nikto -h http://$target:$wports 2> /dev/null 1> $wports-nikto
	echo -e "[*] HTTP/$wports Nikto Scan is ready for review: $nikdur/$wports-nikto" "\a" |tee -a reckon
}

# Subfunction of targetscan for ssl/tls sites
niktohttps(){
	
	niktoruns=$(ps -aux |grep nikto |grep $target |wc -l)	
	while [[ "$niktoruns" -gt "0" ]]; do 
		sleep 60 
		niktoruns=$(ps -aux |grep nikto |grep $target |wc -l)
	done 	

	nikdur=$(pwd)
	echo -e "[*] Running Nikto on HTTP port $wports" |tee -a reckon
	nikto -h https://$target 2> /dev/null 1> $wports-nikto
	echo -e "[*] HTTP/$wports Nikto Scan is ready for review: $nikdur/$wports-nikto" "\a" |tee -a reckon
}

# Subfunction of targetscan
smbvulnscan(){
	echo -e "[*] Running NSE Vuln Scripts for SMB - Target might crash!" |tee -a reckon
	nmap -p 137,139,445 $target --script smb-vuln* -oN nse-smbscan 2> /dev/null 1> /dev/null
	
	smbresults=$(cat nse-smbscan |grep "|" |wc -l)
	
	if [[ "$smbresults" -gt "0" ]]; then
		IFS=$'\n';
		for smbscan in $(cat nse-smbscan |grep "|" |cut -c 3-); do
			echo "[-]   $smbscan" |tee -a reckon
		done
		unset IFS
	else 
	echo -e "[*] NSE Scripts for SMB Failed. No Results." |tee -a reckon
	fi
}

enlnx(){
	enumdir=$(pwd)
	echo -e "[*] Running Enum4Linux on TCP/NetBios ports." |tee -a reckon
	enum4linux $target 1> smb-en4lnx 2> /dev/null
	echo -e "[*] Enum4Linux Report is ready for review: $enumdir/smb-en4lnx" "\a"	 |tee -a reckon
}

smbsafense(){
echo "[*] Running NSE Safe Scripts for SMB " |tee -a reckon
nmap -Pn -sT -sV -sC $target -p 137,139,445  -oN smb-safeenum 2> /dev/null 1> /dev/null
	
	IFS=$'\n'
	for smbenumsafe in $(cat smb-safeenum |grep "|" |cut -c 3-); do
		echo "[-]   $smbenumsafe"
	done
	unset IFS
}

smbscan(){
smbcnt=$(cat quickscan |grep open |grep -v "\-\-top\-ports" |egrep -i '(microsoft-ds|netbios-ssn|samba)'|wc -l)

if [[ "$smbcnt" > "0" ]]; then
echo -e "${GREEN}[SE] Initiating SMB Enumeration ${NC}" |tee -a reckon
	enlnx
	smbsafense
	smbvulnscan
else
	echo "[*] No SMB Ports Detected" |tee -a reckon
fi
}

pendscans(){
	niktoruns=$(ps -aux |grep nikto |grep $target 2> /dev/null |wc -l)	
	
	if [[ "$niktoruns" -gt "0" ]]; then
	echo -e "[*] Added $target to Nikto scan queue" |tee -a reckon
	
		while [[ "$niktoruns" -gt "0" ]]; do 
			sleep 60
			niktoruns=$(ps -aux |grep nikto |grep $target 2> /dev/null |wc -l)	
		done 
	fi
}

singlehost(){
workdir=$(pwd)
mkdir $workdir/$target 2> /dev/null
cd $workdir/$target
echo "" |tee -a reckon

toptcpscan
bannerscan
httpscans
smbscan
pendscans
}

multihost(){
		listcnt=$(cat $userinput |wc -l)
		echo "" |tee -a reckon
		echo -e "${GREEN}[RK] Enumerating $listcnt total hosts ${NC}" |tee -a reckon
		
		workdir=$(pwd)
		mkdir $workdir/$target 2> /dev/null
		cd $workdir/$target


			#alltcpscan
			toptcpscan
			bannerscan
			echo -e "${GREEN}[SS] Initiating Stage 3: Script Scan ${NC}" |tee -a reckon
			httpscans
			smbscan
			pendscans
}

splash(){
echo -e "${GREEN} ---------------------------------${NC}" |tee -a reckon
echo -e "${GREEN} |  _ \ ___  ___| | _____  _ __   ${NC}" |tee -a reckon
echo -e "${GREEN} | |_) / _ \/ __| |/ / _ \| '_ \  ${NC}" |tee -a reckon
echo -e "${GREEN} |  _ <  __/ (__|   < (_) | | | | ${NC}" |tee -a reckon
echo -e "${GREEN} |_| \_\___|\___|_|\_\___/|_| |_| ${NC}" |tee -a reckon
echo -e "${GREEN} ---------------------------------${NC}" |tee -a reckon
echo -e "${GREEN} --- Written by MaliceInChains ---${NC}" |tee -a reckon
}

validate(){
userinput=$1
testinput=$(ping -w1 $userinput 2>&1)
singlehost=$(echo $testinput |grep "bytes of data" |wc -l)
hostlist=$(echo $testinput |grep "Name or service not known" |wc -l)

if [[ "$singlehost" -gt "0" ]];then
	target=$userinput
	singlehost $target
	echo -e "${GREEN}[*] Reckon enumeration is complete${NC}" "\a" "\a" |tee -a reckon

elif [[ "$hostlist" -gt "0" ]];then

filecheck=$(file $userinput |grep "ASCII text" |wc -l)

	if [[ "$filecheck" -gt "0" ]]; then

		for target in $(cat $userinput); do 
			testinput=$(ping -w1 $target 2>&1)
			hostlisttarget=$(echo $testinput |grep "bytes of data" |wc -l)

				if [[ "$hostlisttarget" -gt "0" ]];then
					multihost $target $userinput
				else 
					echo "$target not a valid host"
				fi
		done
	fi
fi
}
splash
validate $*