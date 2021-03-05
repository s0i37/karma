#!/bin/bash

echo 'scanning common ports'
HOME='/home/pi'
time=$(date +'%H:%M:%S_%d.%m.%Y')

nmap -Pn -n $1 -oN "$HOME/$1_$time.txt"
