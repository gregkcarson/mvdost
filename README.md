# MVDOST
Multi-Vector Denial of Service tool for stress testing systems and modelling DoS based attacks to create statistical anomaly and signature based alerting mechanisms.  This is a rough release so it may be buggy but the core functionality is there.

For usage please use -h or --help.

This tool as capable of conducting SYN floods, window size 0 floods, and NTP amplification attacks.  

Multithreading is included, some multithreading values are hard-coded so change at your lesiure.  It doesn't output stats so tcpdump to get meaningful throughput information.  SYNFLOOD and SOCKSTRESS are not bandwidth based attacks, they are resource consumers.

Please note that the NTPAMP module and SOCKSTRESS module do not quit cleanly.  You will have to close your terminal window if you wish to stop the attack.

The sole intent of this tool is to research Denial of Service attack vectors, program them, and run attacks in a controlled and authorized setting so as to model the threat and design signature and statistical detective capabilities for identifying, responding to, and mitigating DoS attacks.  Any malicious use of this tool is done so illegally and without consent of the tool's author.  Play nice people.

Would be fairly simple for someone to fork this, add client/server functionality and turn it into a Distributed Denial of Service attack tool.  I'm just lazy and moving on to other projects.
