#!/bin/bash

echo '[*] scanning common ports'
time=$(date +'%H:%M:%S_%d.%m.%Y')

nmap -Pn -n $1 -oN "nmap-$1_$time.txt"
