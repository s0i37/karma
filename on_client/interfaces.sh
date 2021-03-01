#!/bin/bash

echo 'getting network interfaces via NetBIOS'
HOME='/home/pi'

$HOME/src/netbios.py $1
