# Snort on Pi
Riverside City College Cyber Security Club Raspberry Pi Network Project 

## Goal 
Create a complete network using Raspberry Pi single board computers.

This page is for the Snort IDS/IPS section of our network. 

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
