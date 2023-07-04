# Snort on Pi
Riverside City College Cyber Security Club Raspberry Pi Network Project 

## Goal 
Create a complete network using Raspberry Pi single board computers.

This page is for the Snort IDS/IPS section of our network. 

## Installation:
Installing Snort on Ubuntu 23.04

Source: 
https://www.zenarmor.com/docs/linux-tutorials/how-to-install-and-configure-snort-on-ubuntu-linux

1) Install dependancies for Snort 
	-Use "libpcre3-dev" instead of "libpcre++-dev"

'''
sudo apt install -y build-essential autotools-dev libdumbnet-dev libluajit-5.1-dev libpcap-dev zlib1g-dev pkg-config libhwloc-dev cmake liblzma-dev openssl libssl-dev cpputest libsqlite3-dev libtool uuid-dev git autoconf bison flex libcmocka-dev libnetfilter-queue-dev libunwind-dev libmnl-dev ethtool libjemalloc-dev libpcre3-dev
'''

2) Install LibDAQ (Data Acquisition Library)
'''
git clone https://github.com/snort3/libdaq.git
cd libdaq
'''	

3) Build Snort 3 from source 
'''
wget https://github.com/snort3/snort3/archive/refs/heads/master.zip

unzip master.zip
'''
4) Install Snort 3 
'''
cd build 
make 
sudo make install // important or else program will not launch 
'''

5) After install update linked libraries 
'''
sudo ldconfig
'''

6) Find out which network interface (NIC, network connection) will be used
	-run command: "ip address show"
		-choose option with "BROADCAST,MULTICAST" in name 
			-make not of name 
				-"wlp1s0f0" - name on macbook 
7) Set connection to "promiscous mode"
	-enables NIC to receive all traffic 
		-not just packets destined for IP addres/device 
			-packets/frames intended for other devices can be read 
	-"sudo ip link set dev ens18 promisc on"

8) Check promiscous mode succesfully enabled 
	-"ip address show wlp1s0f0"
		-replace "wlp1s0f0" with name of NIC 

9) Disabling truncation (shortening/breaking up) of large packets 
	-"sudo ethtool -K wlp1s0f0 gro off lro off"

10) Checking that lro and gro are off 
	-"ethtool -k wlp1s0f0 | grep receive-offload"	

12) Create systemd service to keep settings implemented above persistant 
	-replace "wlp1s0f0" with name of NIC 
	1)sudo su 
	2) cat > /etc/systemd/system/snort3-nic.service << 'EOL'
	> [Unit]
	Description=Set Snort 3 NIC in promiscuous mode and Disable GRO, LRO on boot
	After=network.target
	[Service]
	Type=oneshot
	ExecStart=/usr/sbin/ip link set dev wlp1s0f0 promisc on
	ExecStart=/usr/sbin/ethtool -K wlp1s0f0 gro off lro off
	TimeoutStartSec=0
	RemainAfterExit=yes
	[Install]
	WantedBy=default.target
	EOL
'''
11) Reload config settings 
	-"systemctl daemon-reload"

12) Make sure Snort service runs on boot
	-"systemctl enable --now snort3-nic.service"

13) Check current status of snort service 
	-"service snort3-nice status"

14) Create necessarry folders for snort rules 
	-'sudo mkdir /usr/local/etc/rules
	sudo mkdir /usr/local/etc/so_rules/
	sudo mkdir /usr/local/etc/lists/
	sudo touch /usr/local/etc/rules/local.rules
	sudo touch /usr/local/etc/lists/default.blocklist
	sudo mkdir /var/log/snort'

15) Adding test rule to detect ICMP traffic 
	-Gets added to file at /usr/local/etc/rules/local.rules
		-"alert icmp any any -> any any ( msg:"ICMP Traffic Detected"; sid:10000001; metadata:policy security-ips alert; )"

16) Use snort to validate new rule (make sure it works)
	-"snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/rules/local.rules"

17) Running snort to detect and log according to rules 
	-will alert on ICMP traffic
	-"sudo snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/rules/local.rules -i wlp1s0f0 -A alert_fast -s 65535 -k none"

18) To test ICMP rule ping snort server from other PC 
	-should be seeing alerts in terminal 

19) Enable Snort builtin rules 
	1) Navigate to configuration file 
		-"sudo vi /usr/local/etc/snort/snort.lua"
	2) Find "ips" section and uncomment "enable_builtin_rules" 
	3) Add line underneath 
include = RULE_PATH .. "/local.rules",

20) Make sure rules wre added succesuflly 
	"snort -c /usr/local/etc/snort/snort.lua"

21) Start snort with new rules 
	-"sudo snort -c /usr/local/etc/snort/snort.lua -i wlp1s0f0 -A alert_fast -s 65535 -k none"

22) Downloading Community Rules 
	1) sudo su 
	2) cd /usr/local/etc/rules
	3) wget https://www.snort.org/downloads/community/snort3-community-rules.tar.gz
	4) tar xzf snort3-community-rules.tar.gz

23) Adding Community Rules to snort config
	1) "nvim /usr/local/etc/snort/snort.lua"
	2) Set "HOME_NET" equal to ip address of interface (include subnet mask)
		-"192.168.254.129/24"

24) Add following line under "RULE_PATH" existing line 
	-"include = RULE_PATH .. "/local.rules",
include= RULE_PATH .. "/snort3-community-rules/snort3-community.rules", (DO NOT FORGET COMMA AFTER)

25) Check config file for any errors 
	-"snort -c /usr/local/etc/snort/snort.lua"

26) Snort OpenAddID - download from website 
	-download tar and extract in ~/snort_src/ 
		-make directory if not made 
		-"sudo cp -R odp /usr/local/lib/"
			-will copy odp (which is extracted from tar) to /local/lib 
	-feature of snort that allows user to detect and block/monitor which application is being accessed (Facebook, gaming, VPN)
	-detects types of popular traffic

27) Modify snort config and add appid 
	-"sudo nvim /usr/local/etc/snort.lua"
	-add the following to appid section: 
	'app_detector_dir = '/usr/local/lib',
	log_stats = true, 
	-NOTES: double check spelling "lib" not "lub"
	do not forget commas 

28) Check everything is good in config file 
	-"sudo snort -c /usr/local/etc/snort/snort.lua"

29) Add rule to detect facebook traffic to local.rules 
	1) Navgiate to location of rules 
	-"cd /usr/local/etc/rules"
	2) Add new rule to local.rules 
	"alert tcp any any -> any any ( msg:"Facebook Detected"; appids:"Facebook"; sid:10000002; metadata:policy security-ips alert; )"

30) Check everything is okay in file 
	"snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/rules/local.rules"

31) Run Snort with new rule 
	-As sudo:
	"snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/rules/local.rules -i wlp1s0f0 -A alert_fast -s 65535 -k none"
	-replace wlp1s0f0 with name of NIC 	

32) DEMO: attempt to connect to facebook and see alerts in terminal 
	-this is demo of AppID 
	-this is demo of rules added

33) Change "snort.lua" config file to include the following 
	-"cd /usr/local/etc/snort"
	-uncomment alert_fast
		-"alert_fast = {file = true, 
		packet = false,
		limit = 10, 
		}"

34) Check that configuration file is working 
	-check for syntax, settings correctly applied 
	-"snort -c /usr/local/etc/snort/snort.lua"

35) Run snort and specify where to create log file using "-l /var/log/snort"
	-"sudo snort -c /usr/local/etc/snort/snort.lua -i wlp1s0f0 -s 65535 -k none -l /var/log/snort"
	-also remove "-A alert_fast"

36) Check that rule works by navigating to facebook.com 

37) Find alerts from snort scan in 
	-"/var/log/snort/alert_fast.txt"
	-nothing will be printed to console 

38) Create "snort" user to create systemd service for snort 
	-"useradd -r -s /usr/sbin/nologin -M -c SNORT_IDS snort"
		-adding new user named snort without a login 

39) Giving new user "snort" ownership of logs 
	-"sudo chmod -R 5775 /var/log/snort"
	-"sudo chown -R snort:snort /var/log/snort"

40) Creating systemd service
	-had to go find out how to add systemd service 
	-"https://www.shubhamdipt.com/blog/how-to-create-a-systemd-service-in-linux/"
	-"cd /etc/systemd/system"
	-"touch snort3.service"
	-"[Unit]
Description=Snort3 NIDS Daemon
After=syslog.target network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/snort -c /usr/local/etc/snort/snort.lua -s 65535 -k none -l /var/log/snort -D -u snort -g snort -i ens18 -m 0x1b --create-pidfile
ExecStop=/bin/kill -9 $MAINPID
[Install]
WantedBy=multi-user.target"
	-"sudo systemctl enable snort3"
	-"sudo service snort3 start"
	-"sudo service snort3 status"

41) In case of any errors runn following command:
	"sudo journalctl -u snort3.service"
	

So Far: 
	-have snort set up with community and local rules 
	-working on adding Registered rules
		-cannot get these to work 
		-will come back to Registered Rules 


-) Getting help in Snort 
	-'snort --help'
		-overview of different ways you can get help in snort (help on modules, rules, etc)
	or
	-snort -?
		-all command line options for snort

## Working Notes 
These are not steps to follow but merely notes. 

Snort on R Pi 
- [ ] Snort monitors network traffic 
    - [ ] Free and open-source 
        - [ ] Two versions: 2 & 3 
            - [ ] Version 2 is most widely used currently but Version 3 is newer
    - [ ] Monitors traffic using rules 
        - [ ] Network traffic is analyzed for patterns 
            - [ ] Similar to how a firewall works 
        - [ ] Three types of rule sets 
            - [ ] Community - free made by community 
            - [ ] Registered - made by Talos but need to have an account 
            - [ ] Subscription - paid for rules using subscription 
    - [ ] Detects network intrusions 
    - [ ] Can also be set up to block intrusions 
        - [ ] Becomes an IPS (intrusion prevention system)
        - [ ] Uses rules to “drop” packets
    - [ ] IDS 
    - [ ] Creates logs of malicious activity and alerts user 
        - [ ] These logs are then sent to a SIEM (splunk)
            - [ ] Needs to be in json format for splunk 
- [ ] Splunk analyzes that traffic 
