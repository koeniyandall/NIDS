# NIDS
Network-Based IDS System Using C++

# Summary / Overview
Libpcap was used as the packet handling engine. With libpcap, I calculated the offset and size of each tcp packet field from ethernet->IP->TCP->payload. After deciphering the packet, I searched the payload for various hueristics and known threats such as Telnet connections aswell as SSH connections. With various other rules, this NIDS is able to effectively parse packets and detect suspicious network behavior, aswell as give alerts if a certain rule has been matched. As of right now, this NIDS is able to detect port based intrusions aswell as other malware through the technique of payload parsing, however, I would love to later work on "harder to code" attacks such as SYN floods.

# Future
As for future additions to this project, I would like to implement the following:
  1. Website for the project
  2. AI/ML implementation for anamoly based IDS abilities
  3. Allow users to write custom rules
  4. Ability to Detect SYN floods (requires further TCP parsing)
There are definitely other features that I would love to add, but these are definitely the most pertinent. After all, my goal with making this NIDS was to actually ship it as a website for people with limited networking knowledge to use. Because of this, I believe that while there will be a feature for custom rule sets, the NIDS is going to come with a default rule set that will cover common attacks like SSH, Telnet, SQL, and shell commands.

# Usage
1. Clone the repo
2. Compile - clang++ -std=c++11 nids.cpp -lpcap -o nids
3. Run - sudo ./nids (optional: if your on mac, it will default use en0. however if your on Windows/Linux, you will need to give your interface as a command line arguement ex: sudo ./nids eth0

![Program Running](assets/Screenshot%2025-09-04%at%5.18.46%PM.png)

# What I Learned
The knowledge of both low level network progamming in C and C++ along with the knowledge of network packets is invaluable. I now know not only the structure of netowrk packets but also how to decipher them along with use them to catch intrusions. This also gave me familiarity with libpcap aswell cybersecurity/SOC exposure.
