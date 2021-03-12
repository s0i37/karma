#!/bin/bash

echo '[*] writing trafic'
time=$(date +'%H:%M:%S_%d.%m.%Y')

tcpdump -i "$1" -nn -w "$2_$time.pcap"
