#!/bin/bash

WAIT=2
DPORT=445

if nc -nw $WAIT $1 $DPORT < /dev/null 2> /dev/null; then
	echo '[*] getting local admins'
	net rpc group members administrators -I $1 -U '1%1'
	net rpc group members Администраторы -I $1 -U '1%1'
fi