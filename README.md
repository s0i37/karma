# karma

Wi-Fi clients attacking.

Many of Wi-Fi clients send broadcast known network names.

Karma respond to each new announced network as starting required network.

If client connects to this network Karma will launch every attack scenario, described by attacker.

### Installation

Core engine:

`sudo pip3 install scapy mac-vendor-lookup netaddr argparse colorama getkey`

Scripts engine:

```
cd /opt/
git clone https://github.com/samyk/poisontap
git clone https://github.com/lgandx/Responder responder
	sudo ln -s /opt/responder/Responder.py /usr/local/bin/responder
	sudo ln -s /opt/responder /usr/share/responder
git clone https://github.com/threat9/routersploit
	sudo ln -s /opt/routersploit/rsf.py /usr/local/bin/rsf.py
git clone https://github.com/Sab0tag3d/SIET
sudo apt install python3 php nodejs
sudo apt install nmap ngrep hydra medusa samba-common-bin smbclient sslsplit socat inotify-tools samba python-impacket
sudo apt install freerdp2-x11 rdesktop surf graphicsmagick-imagemagick-compat xserver-xorg-core xinit
sudo apt install python3-pip
sudo pip3 install pysmb
echo 'export PATH="$PATH:/usr/share/doc/python-impacket/examples"' >> ~/.bashrc
echo 'export PATH="$PATH:/usr/share/doc/python-impacket/examples"' >> /root/.bashrc
wget https://github.com/HynekPetrak/detect_bluekeep.py/blob/master/detect_bluekeep.py -O /opt/bluekeep/bluekeep_check.py
```

### Setup

You will need 2 or 3 logical (or better physical) NICs.

First one used for monitoring broadcast Wi-Fi frames (monitor mode), second and third ones used for starting new wireless network with hostapd as OPN and WPA.

For creating additional logical interface (may work not always):

```
sudo iw phy0 interface add mon0 type monitor
sudo ifconfig mon0 up
sudo ifconfig wlan0 up
```

### Running

Attacking through OPN Wi-Fi network:

`sudo ./karma.py -mon mon0 -opn wlan0`

Attacking through OPN and WPA Wi-Fi networks:

`sudo ./karma.py -mon mon0 -opn wlan0 -wpa wlan1`

If required ESSID found in "handshakes" folder Karma will start WPA network with presented password.

### Customization

Karma also perform various attack scenario for connection clients.

Every scenarion presented as any script in respectively folder:

- `on_client/` - Run each script for every new IP

- `on_network/` - Run each script for starting new Wi-Fi network

- `on_handshake/` - Custom handling half-handshakes

- `on_probe/` - May be used for logging clients announcing
