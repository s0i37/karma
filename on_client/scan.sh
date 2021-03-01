#!/bin/bash

echo 'scanning common ports'
HOME='/home/pi'

nmap -Pn -n $1 -oN "$HOME/$1_$RANDOM.txt"
