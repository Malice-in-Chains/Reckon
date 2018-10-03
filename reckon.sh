#!/bin/bash
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
tports=100
round=1

toptcpscan(){ # Conducts a quick scan of top ___ ports.
nmap -Pn -sT $target -oN quickscan --top-ports $tports --open >/dev/null 2>&1;
cat quickscan |grep open |grep -v nmap > .openports
echo -e "${GREEN}[!]${NC}   QuickScan identified $(cat quickscan |grep open |grep -v nmap |wc -l) open ports on $target." "\a"  |tee -a reckon
for nports in $(cat quickscan |grep open |grep -v nmap |awk '{print$1}'); do 
	echo "[-]      $nports" |tee -a reckon
done
}

versionscan(){ # Conduct -sV scan on previously identified open ports
for oports in $(cat .openports |grep open |grep -v "\-\-top\-ports" |awk '{print$1}' |awk -F "/" '{print$1}'); do
	nmap -Pn -sT -sV $target -p $oports -oN $oports-version 2> /dev/null 1> /dev/null
	trn=$(cat $oports-version |grep open |awk -F "$(cat $oports-version |grep open |cut -d " " -f1,2,3,4)" '{print$2}' |sed 's/  //g')
	vrn=$(echo $trn |sed 's/  / /g')
	srv=$(cat $oports-version |grep open |awk '{print$3}')

	if [[ -z "$vrn" ]] | [[ "$vrn" == "?" ]]; then
		vrn="Unable to Enumerate Service"
		echo -e "[-]      $oports - $vrn"  |tee -a reckon
	else
		echo -e "[-]      $oports/tcp is running $srv via $vrn"  |tee -a reckon
	fi	
done

if [[ "$round" == "1" ]]; then
	cat *-version |grep open |grep -v nmap > .openports
else
	cat *-version |grep open |grep -v nmap > .openports
		for qsopen in $(cat quickscan |grep open |grep -v nmap |awk '{print$1}');do
			cat .openports |grep open |grep -v "$qsopen" >> .newports
			mv .newports .openports
		done
	cat .openports |sort -g > .sortedports
	mv .sortedports .openports		
fi
}

httpenum(){ # Runs various scanners against http and https ports
	for wports in $(cat .openports |grep http |awk '{print$1}' |awk -F "/" '{print$1}' |sort -g); do
		echo -e "${GREEN}[!]${NC}   Starting HTTP enumeration on port $wports." |tee -a reckon
		pullheaders
		echo -e "${GREEN}[!]${NC}    Queued Nikto scan of http port $wports." |tee -a reckon
		niktohttp&
		nsesafe
		#dirbscan&	
	done
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
		echo "${GREEN}[!]${NC} Unable to pull HTTP headers." |tee -a reckon
	else
		echo -e "${GREEN}[!]${NC}    Pulling HTTP headers." |tee -a reckon
			for info in $(cat $wports-header |grep ":" |egrep -v "Date:"); do
				echo "[-]      $info" |tee -a reckon
			done
	fi
	unset IFS
}

niktohttp(){ # Runs one nikto scan at a time against HTTP ports
	IFS=$'\n';
	niktoruns=$(ps -aux |grep nikto |grep $target |wc -l)	
	
	while [[ "$niktoruns" -gt "0" ]]; do 
		sleep 60 
		niktoruns=$(ps -aux |grep nikto |grep $target |wc -l)
	done 
	
	nikdur=$(pwd)
	
	if [[ "$wports" == "443" ]]; then
		nikto -h https://$target  2> /dev/null 1> $wports-nikto
		echo -e "${GREEN}[!]${NC} The Nikto scan against https://$target has completed." "\a" |tee -a reckon
	else
		nikto -h http://$target:$wports 2> /dev/null 1> $wports-nikto
		echo -e "${GREEN}[!]${NC} The Nikto scan against http://$target:$wports has completed." "\a" |tee -a reckon
	fi

	for info in $(cat $wports-nikto |grep + |egrep -v '(Target IP:|Target Hostname:|Target Port:|Start Time:|End Time:|host\(s\) tested|reported on remote host)' |sed 's/+ //g'); do
		echo "[-]      $info" |tee -a reckon
	done

	unset IFS
}

nsesafe(){ # Runs safe NSE scripts
echo -e "${GREEN}[!]${NC}    Running NSE scripts against tcp port $wports." |tee -a reckon
nmap -Pn -sT -sV -sC $target -p $wports -oN $wports-nse 2> /dev/null 1> /dev/null
results=$(cat $wports-nse |grep "|" |wc -l)

if [[ "$results" -gt "0" ]]; then
	IFS=$'\n';
	for nsescript in $(cat $wports-nse |grep "|" |cut -c 3-); do
		echo "[-]      $nsescript" |tee -a reckon
	done
	unset IFS
else
echo "[-]      No results from NSE scripts." |tee -a reckon
fi
}

enum4linux(){ # Runs enum4linux
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
		echo "[-]      $smbenumsafe"
	done
	unset IFS
}

smbdangerous(){ # Runs all smb-vuln NSE scripts. DANGER: This could crash the target.
	echo -e "${GREEN}[!]${NC} Running NSE Vuln Scripts for SMB - Target might crash!" |tee -a reckon
	nmap -p 137,139,445 $target --script smb-vuln* -oN nse-smbscan 2> /dev/null 1> /dev/null
	
	smbresults=$(cat nse-smbscan |grep "|" |wc -l)
	
	if [[ "$smbresults" -gt "0" ]]; then
		IFS=$'\n';
		for smbscan in $(cat nse-smbscan |grep "|" |cut -c 3-); do
			echo "[-]      $smbscan" |tee -a reckon
		done
		unset IFS
	else 
	echo -e "${GREEN}[!]${NC} NSE Scripts for SMB Failed. No Results." |tee -a reckon
	fi
}

smbscan(){ # Checks quick scan results for SMB, and NetBios ports, then runs SMB enum functions
smbcnt=$(cat .openports |grep open |grep -v "\-\-top\-ports" |egrep -i '(microsoft-ds|netbios-ssn|samba)'|wc -l)

if [[ "$smbcnt" > "0" ]]; then
echo -e "${GREEN}[SE]${NC} Starting SMB enumeration." |tee -a reckon
	enum4linux
	#smbdangerous
#else
#	echo "${GREEN}[!]${NC} No SMB Ports Detected" |tee -a reckon
fi
}

enumscans(){
	wports=$(cat .openports |grep http |wc -l)
		if [[ "$wports" -gt "0" ]]; then
			httpenum
		fi

	smbports=$(cat .openports |egrep -i '(microsoft-ds|netbios-ssn|samba)'|wc -l)
		if [[ "$smbports" -gt "0" ]]; then
			smbscan
		fi

	otherports=$(cat .openports |egrep -vi '(microsoft-ds|netbios-ssn|samba|http)' |wc -l)
		if [[ "$otherports" -gt "0" ]];then
			for wports in $(cat .openports |egrep -vi '(microsoft-ds|netbios-ssn|samba|http)' |awk -F "/" '{print$1}' |sort -g);do
				nsesafe
			done
		fi
}


alltcpscan(){ # Scans for all TCP ports but excludes previously discovered ports in output.
nmap -Pn -sT $target -oN fullscan -p- --open >/dev/null 2>&1;
cat fullscan |grep open |grep -v nmap > .fsopen

for qsopen in $(cat quickscan |grep open |grep -v nmap |awk '{print$1}');do
	cat .fsopen |grep open |grep -v "$qsopen" >> .fsopen1
	mv .fsopen1 .fsopen
done

delta=$(cat .fsopen |wc -l)

if [[ "$delta" -gt "0" ]]; then
	echo -e "${GREEN}[!]${NC}   FullScan identified $(cat .fsopen |wc -l) additional ports on $target." "\a"  |tee -a reckon
	for nports in $(cat .fsopen |awk '{print$1}'); do 
		echo "[-]      $nports" |tee -a reckon
	done
	mv .fsopen .openports

	echo -e "${GREEN}[S3]${NC} Running VersionScan against $(cat .openports |wc -l) open ports"  |tee -a reckon
	round=2
	versionscan
	
	echo -e "${GREEN}[S4]${NC} Running EnumScans against $(cat .openports |wc -l) open ports." |tee -a reckon
	enumscans
else
	echo -e "${GREEN}[!]${NC}   FullScan complete, no additional ports identified."
fi
}

scanqueue(){ # Holds the terminal until all scans have completed.
	niktoruns=$(ps -aux |grep nikto |grep $target 2> /dev/null |wc -l)	
	
	if [[ "$niktoruns" -gt "0" ]]; then
	
		while [[ "$niktoruns" -gt "0" ]]; do 
			sleep 60
			niktoruns=$(ps -aux |grep nikto |grep $target 2> /dev/null |wc -l)	
		done 
	fi
}

mainfunction(){ # Runs enumeration functions for a single host $1 user arguement.
workdir=$(pwd)
mkdir $workdir/$target 2> /dev/null
cd $workdir/$target
echo -e "${GREEN}[S1]${NC} Testing directory created at: $(pwd) "

echo -e "${GREEN}[S2]${NC} Running QuickScan against the top $tports tcp ports." |tee -a reckon
toptcpscan

echo -e "${GREEN}[S3]${NC} Running VersionScan against $(cat .openports |wc -l) open ports"  |tee -a reckon
versionscan

echo -e "${GREEN}[S4]${NC} Running EnumScans against $(cat .openports |wc -l) open ports." |tee -a reckon
enumscans

echo -e "${GREEN}[S5]${NC} Running FullScan against all tcp ports." |tee -a reckon
alltcpscan

scanqueue
echo -e "${GREEN}[!]${NC} Reckon enumeration is complete" "\a" "\a" |tee -a reckon
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
		echo -e "[-] ./reckon.sh /home/malice/hostlist.txt "
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
	mainfunction $target

elif [[ "$hostlist" -gt "0" ]];then
filecheck=$(file $userinput |grep "ASCII text" |wc -l)

	if [[ "$filecheck" -gt "0" ]]; then
		listcnt=$(cat $userinput |wc -l)	
			echo -e "${GREEN}[!]${NC} Host list detected. Scanning $listcnt total hosts."
			for target in $(cat $userinput); do 
				testinput=$(ping -w1 $target 2>&1)
				hostlisttarget=$(echo $testinput |grep "bytes of data" |wc -l)

					if [[ "$hostlisttarget" -gt "0" ]];then
						mainfunction $target $userinput
					else 
						echo -e "${RED}[ER] Host list error: $1 is not a valid IP or domain. ${NC}"
					fi
			done
	else 
		echo ""
		echo -e "${RED}[ER]  Error: $1 is not a valid IP, domain, or host list. ${NC}"
		echo ""
		usage
	fi
fi
}
splash
validate $*
