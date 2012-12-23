#mongol

Mongol.py is a tool that was inspired by a research paper[0] that described the physical locations and number of routers
acting for the Great Firewall (GFW) of China.  These could be both filtering devices (if they are inline) or mirror routers
that are forking the traffic to a filter device. 

Mongol is effectively a implementation of the research tool used by Xu etc all, with the intent to demystify some aspects of the GFW.
It is built using scapy[1] for some of the TCP header modification requirements


[0]  http://pam2011.gatech.edu/papers/pam2011--Xu.pdf

[1]  http://www.secdev.org/projects/scapy/

##Usage

sudo python mongol.py -i hostslist.txt -o outputfilename.txt [-k KEYWORD]
	-i hostlist.txt: required newline seperated list of hosts to scan
	-o outputfile.txt: File to write data out too
	-h: Show this message
	-k KEYWORD: Overwrite the default keyword of 'tibet@lk'

##How it works

Mongol MUST be run on a device that is Internet facing, aka NOT behind a router or firewall.

Mongol works by stimulating the keyword filtering that the GFW uses.  First we create a test connection and check that the 
site is indeed hosting a webserver and is live.  Then by sending the stimulus 'tibet@lk' (the 'a' is replaced to prevent 
this site from being blocked) the keyword filtering will become active.  Finally we run a TCP header traceroute and find 
the last hop before RST packets are sent back.  RST packets are the GFW's method of stopping connections with filtered 
keywords.

The more websites you have in your input file the more devices you will beable to find.  I recommend a geographically diverse
list as well.
