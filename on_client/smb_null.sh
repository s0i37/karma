#!/bin/bash

WAIT=2
DPORT=445

if nc -nw $WAIT $1 $DPORT < /dev/null 2> /dev/null; then
	echo '[*] checking SMB null session'
	#smbclient -U 1%1 -L $1
	if smbclient -U 1%1 -L $1 | grep -q 'Sharename'; then
		nmap -Pn -n -p 445 $1 --script 'smb-enum-*'
	fi
fi
