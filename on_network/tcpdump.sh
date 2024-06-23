#!/bin/bash

echo '[*] writing trafic'
time=$(date +'%d.%m.%Y_%H:%M:%S')

tcpdump -i "$1" -nn -w "${2}_${time}_${RANDOM}.pcap"
