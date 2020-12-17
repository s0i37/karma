#!/bin/bash

WAIT_SEC=1
DPORT=445

nc -w $WAIT_SEC $1 $DPORT 2> /dev/null && {
	echo 'getting local admins'

	net rpc group members administrators -I $1 -U '1%1'
	net rpc group members Администраторы -I $1 -U '1%1'
}