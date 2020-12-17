#!/bin/bash

WAIT_SEC=1
DPORT=445

nc -w $WAIT_SEC $1 $DPORT 2> /dev/null && {
	echo 'checking MS17-010'

	python2 /home/soier/src/MS17-010/checker.py $1
}