#!/bin/bash

echo 'scanning common ports'

nmap -Pn -n $1 -oN "$1.txt"
