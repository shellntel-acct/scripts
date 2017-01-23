#!/usr/bin/python
# Author: Hans Lakhan
#######################
# Requirements:
#	boto:		pip install -U boto
#
#######################
# To Do
#	1) Add support for config?
#	2) Change os.system() to subproccess.Popen to manage STDOUT, STDERR better
#	3) add support for re-establishing tunnels
#	4) Add support for connecting to other clusters
#	5) Trim Log Output Time
#	6) Cleanup Try/Catch statments
#	7) Clean STDOUT from iproute changes
#
#######################
import boto.ec2
import os
import argparse
import time
import sys
import subprocess
import fcntl
import struct
import socket
import hashlib
import signal
import datetime
import re
from subprocess import Popen, PIPE, STDOUT

#############################################################################################
# Handle Colored Output
#############################################################################################

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def error(msg):
	print "[" + bcolors.FAIL + "!" + bcolors.ENDC + "] " + msg
def success(msg):
	print "[" + bcolors.OKGREEN + "*" + bcolors.ENDC + "] " + msg 
def warning(msg):
	print "[" + bcolors.WARNING + "~" + bcolors.ENDC + "] " + msg
def debug(msg):
	if args.v:
		timestamp = datetime.datetime.now()
		print "[i] " + str(timestamp) + " : " + msg

#############################################################################################
# Handle Logging
#############################################################################################

def log(msg):
	
	timestamp = datetime.datetime.now()
	logfile = open("/tmp/" + logName, 'a')
	logfile.write(str(timestamp))
	logfile.write(" : " + str(msg))
	logfile.write("\n")
	logfile.close()


#############################################################################################
# Handle SigTerm & Clean up
#############################################################################################
def cleanup(signal, frame):
	# Time to clean up
	print "\n"
	success("Roger that! Shutting down...")

	if args.v:
		print 'In debug mode. Press enter to continue.'
                null = raw_input()

        # Connect to EC2 and return list of reservations
        try:
                success("Connecting to Amazon's EC2...")
                #cleanup_conn = boto.ec2.connect_to_region(region_name=args.region, aws_access_key_id=args.key_id, aws_secret_access_key=args.access_key)
		cleanup_conn = boto.ec2.connect_to_region(region_name=args.region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
        except Exception as e:
                error("Failed to connect to Amazon EC2 because: %s" % e)

        cleanup_reservations = cleanup_conn.get_all_instances(filters={"tag:Name" : nameTag, "instance-state-name" : "running"})

	# Grab list of public IP's assigned to instances that were launched
	allInstances = []
	for reservation in cleanup_reservations:
       		for instance in reservation.instances:
                	if instance.ip_address not in allInstances:
                        	if (instance.ip_address):
                                	allInstances.append(instance.ip_address)
	debug("Public IP's for all instances: " + str(allInstances))
	
	# Flush iptables 
	success("Restoring iptables....")
	os.system("iptables -t nat -F")
	debug("SHELL CMD: iptables cmd: iptables -t -nat -F")
	os.system("iptables -F")
	debug("SHELL CMD: iptables cmd: iptables -F")
	os.system("iptables-restore  < /tmp/%s" % iptablesName)

	# Cleaning routes
	success("Correcting Routes.....")
	interface = args.num_of_instances
	for host in allInstances:
        	os.system("route del %s dev %s" % (host, args.interface))
		debug("SHELL CMD: route del " + host + " dev " + args.interface)
	os.system("ip route del default")
	debug("SHELL CMD: ip route del default")
	os.system("ip route add default via %s dev %s" % (defaultgateway, args.interface))
	debug("SHELL CMD: ip route add default via " + defaultgateway + " dev " + args.interface)

	# Terminate instance
	success("Terminating Instances.....")
	for reservation in cleanup_reservations:
        	for instance in reservation.instances:
                	instance.terminate()

	warning("Pausing for 90 seconds so instances can properly terminate.....")
	time.sleep(90)

	# Remove Security Groups
	success("Deleting Amazon Security Groups.....")
	try:
        	cleanup_conn.delete_security_group(name=securityGroup)
	except Exception as e:
        	error("Deletion of security group failed because %s" % e)

	# Remove Key Pairs
	success("Removing SSH keys.....")
	try:
        	cleanup_conn.delete_key_pair(key_name=keyName)
	except Exception as e:
        	error("Deletion of key pair failed because %s" % e)

	# Remove local ssh key
	debug("SHELL CMD: rm -f " + homeDir + "/.ssh/" + keyName + ".pem")
	subprocess.Popen("rm -f %s/.ssh/%s.pem" % (homeDir, keyName), shell=True)

	# Remove local routing
	success("Restoring local routing....")
	debug("SHELL CMD: echo 0 > /proc/sys/net/ipv4/ip_forward")
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

	# remove iptables saved config
	success("Removing local iptables save state")
	debug("SHELL CMD: rm -rf  /tmp/%s" + iptablesName)
	subprocess.Popen("rm /tmp/%s" % iptablesName, shell=True)

	# Log then close
	log("ProxyCannon Finished.")

	success("Done!")
	
	sys.exit(0)

#############################################################################################
# Rotate Hosts 
#############################################################################################

def rotate_hosts():
	#connect to EC2 and return list of reservations
        
	while True:
		retry_cnt = 0
                while retry_cnt < 6:
                	if retry_cnt == 5:
                        	error("giving up...")
                                cleanup("foo", "bar")
                        try:
                                debug("Connecting to Amazon's EC2.")
	                        rotate_conn = boto.ec2.connect_to_region(region_name=args.region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
				retry_cnt = 6
                        except Exception as e:
                                warning("Failed to connect to Amazon EC2 because: %s. Retrying..." % e)
				retry_cnt = retry_cnt + 1
                                time.sleep(+int(retry_cnt))
		
		retry_cnt = 0
                while retry_cnt < 6:
                        if retry_cnt == 5:
                                error("giving up...")
                                cleanup("foo", "bar")
                        try:
                                rotate_reservations = rotate_conn.get_all_instances(filters={"tag:Name" : nameTag, "instance-state-name" : "running"})
				retry_cnt = 6
                        except Exception as e:
                                warning("Failed to connect to Amazon EC2 because: %s (rotate_reservations). Retrying..." % e)
				retry_cnt = retry_cnt + 1
                                time.sleep(+int(retry_cnt))
		
		# interface = 0
	        for reservation in rotate_reservations:
        		for instance in reservation.instances:
			
				# build ip filter list

				# Connect to EC2 and return list of reservations
                                retry_cnt = 0
                                while retry_cnt < 6:
					if retry_cnt == 5:
						error("giving up...")
						cleanup("foo", "bar")
                                	try:
						ipfilter_conn = boto.ec2.connect_to_region(region_name=args.region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
						retry_cnt = 6
					except Exception as e:
						warning("Failed to connect to Amazon EC2 because: %s (ipfilter_con). Retrying..." % e)
						retry_cnt = retry_cnt + 1
						time.sleep(+int(retry_cnt))
				
                                retry_cnt = 0
                                while retry_cnt < 6:
                                        if retry_cnt == 5:
                                                error("giving up...")
                                                cleanup("foo", "bar")
                                        try: 
                                                ipfilter_reservations = ipfilter_conn.get_all_instances(filters={"tag:Name" : nameTag, "instance-state-name" : "running"})
						retry_cnt = 6
                                        except Exception as e:
                                                warning("Failed to get reservations because: %s (ipfilter_reservations). Retrying..." % e)
						retry_cnt = retry_cnt + 1
                                                time.sleep(+int(retry_cnt))
			
			        # Grab list of public IP's assigned to instances that were launched
			        ipfilter = []
			        for ipfilter_reservation in ipfilter_reservations:
			                for ipfilter_instance in ipfilter_reservation.instances:
			                	ipfilter.append(ipfilter_instance.ip_address)
			        debug("Public IP's for all instances: " + str(ipfilter))

				host = instance.ip_address
				debug("Rotating: " + str(host))
	
				# Build New Route table with $times_run being set to weight 256
				weight = 1
				nexthopcmd = "ip route replace default scope global "
	
				route_interface = 0
	
				while route_interface < args.num_of_instances:
				        if (route_interface == address_to_tunnel[str(host)]):
						weight = 1
					else:
						weight = 2
					nexthopcmd = nexthopcmd + "nexthop via 10." + str(route_interface) + ".254.1 dev tun" + str(route_interface) + " weight " + str(weight) + " "
				        route_interface = route_interface + 1
	
				debug("SHELL CMD: " + nexthopcmd)	
				retcode = subprocess.call(nexthopcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
                                if str(retcode) != "0":
                                        error("ERROR: Failed to install new route")
                                        debug("retcode: " + str(retcode))
					cleanup("foo", "bar")
				#os.system("%s" % nexthopcmd)
	
				stat = 1
				while True:
	
					# check to validate that no sessions are established
					# Check TCP RX&TX QUEUE
					# netstat -ant | grep ESTABLISHED | grep 52.90.212.53 | awk '{print $2$3}'
					p1 = subprocess.Popen(['netstat', '-ant'], stdout=subprocess.PIPE)
					p2 = subprocess.Popen(['grep', 'ESTABLISHED'], stdin=p1.stdout, stdout=subprocess.PIPE)
					p3 = subprocess.Popen(['grep', host], stdin=p2.stdout, stdout=subprocess.PIPE)
					awkcmd = ['awk', '{print $2$3}'] # had some problems escaping the single quotes, went with this
					p4 = subprocess.Popen(awkcmd, stdin=p3.stdout, stdout=subprocess.PIPE)
					stat,err = p4.communicate()
					p1.stdout.close()
					p2.stdout.close()
					p3.stdout.close()
					p4.stdout.close()
					debug("Connection Stats " + stat.strip())
					if (int(stat) > 0):
			       	 		debug("Connection is in use, sleeping and trying again in .5 seconds")
						time.sleep(.5)
					else:
       		 				debug("Connection is free")
						break
				
				# Killing ssh tun cmd
				killcmd = "kill $(ps -ef | grep ssh | grep %s | awk '{print $2}')" % host
				debug("SHELL CMD: " + killcmd)
				
				retcode = subprocess.call(killcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
                                if str(retcode) != "-15":
                                        error("ERROR: Failed to kill ssh tunnel for %s." % host)
					debug("retcode: " + str(retcode))
				
				# remove iptables rule allowing SSH to EC2 Host
				os.system("iptables -t nat -D POSTROUTING -d %s -j RETURN" % host)
				debug("SHELL CMD: iptables -t nat -D POSTROUTING -d " + host + " -j RETURN")			
		
				# Nat outbound traffic going through our tunnels
			        os.system("iptables -t nat -D POSTROUTING -o tun%s -j MASQUERADE" % address_to_tunnel[str(host)])
				debug("SHELL CMD: iptables -t nat -D POSTROUTING -o tun" + address_to_tunnel[str(host)] + " -j MASQUERADE")
	
				# Remove Static Route to EC2 Host
				os.system("ip route del %s" % host)
				debug("SHELL CMD: ip route del " + host)
	
				# Remove from route table		
       	                	# Build New Route table with $times_run being set to weight 256
       	 	                weight = 1
       	        	        nexthopcmd = "ip route replace default scope global "

	                        route_interface = 0
	
       		                # Change to if not
				while route_interface < args.num_of_instances:
       	                        	if (int(route_interface) == int(address_to_tunnel[str(host)])):
                                        	weight = 1
	                                else:
       	                                	weight = 1
       	                         		nexthopcmd = nexthopcmd + "nexthop via 10." + str(route_interface) + ".254.1 dev tun" + str(route_interface) + " weight " + str(weight) + " "
                               		route_interface = route_interface + 1

	                        debug("SHELL CMD: " + nexthopcmd)
       	                 	retcode = subprocess.call(nexthopcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
                                if str(retcode) != "0":
                                        error("ERROR: Failed to install new route")
                                        debug("retcode: " + str(retcode))
                                        cleanup("foo", "bar")

				#os.system("%s" % nexthopcmd)

				# Requesting new IP allocation
				try:
					new_address = rotate_conn.allocate_address()
				except Exception as e:
					error("Failed to obtain a new address because: " + str(e))
					cleanup("foo", "bar")
				debug("Temporary Elastic IP address: " + new_address.public_ip)
			
				time.sleep(5)
				# Associating new address
				rotate_conn.associate_address(instance.id, new_address.public_ip)

				## At this point, your VM should respond on its public ip address. NOTE: It may take up to 60 seconds for the Elastic IP address to begin working
				debug("Sleeping for 30s to allow for new IP to take effect")
				time.sleep(30)

				# Remove assocation forcing a new public ip
				try:
					rotate_conn.disassociate_address(new_address.public_ip)
				except Exception as e:
					error("Failed to dissassociate the address " + str(new_address.public_ip) + " because: " + str(e))
					cleanup("foo", "bar")
				debug("Sleeping for 60s to allow for new IP to take effect")
				time.sleep(60)
				
				# Return the Second Elastic IP address back to address pool
				try:
					rotate_conn.release_address(allocation_id=new_address.allocation_id)
				except Exception as e:
					error("Failed to release the address " + str(new_address.public_ip) + " because: " + str(e))
					cleanup("foo", "bar")

				# Connect to EC2 and return list of reservations
                                try:
                                        ip_list_conn = boto.ec2.connect_to_region(region_name=args.region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
                                except Exception as e:
                                        error("Failed to connect to Amazon EC2 because: %s" % e)

                                ip_list_reservations = ip_list_conn.get_all_instances(filters={"tag:Name" : nameTag, "instance-state-name" : "running"})

                                # Grab list of public IP's assigned to instances that were launched
                                all_addresses = []
                                for ip_list_reservation in ip_list_reservations:
                                        for ip_list_instance in ip_list_reservation.instances:
                                                all_addresses.append(ip_list_instance.ip_address)
                                debug("Public IP's for all instances: " + str(all_addresses))
	
				swapped_ip = ''
				#print("all_addresses: " + str(all_addresses))
				for address in all_addresses:
					if address not in ipfilter:
						debug("found new ip: " + str(address))
						swapped_ip = str(address)
	
				# Add static routes for our SSH tunnels
	       	                os.system("ip route add %s via %s dev %s" % (swapped_ip, defaultgateway, args.interface))
				debug("SHELL CMD: ip route add " + swapped_ip + " via " + defaultgateway + " dev " + args.interface)
	
	 	      		# Establish tunnel interface
       	 			sshcmd = "ssh -i %s/.ssh/%s.pem -w %s:%s -o StrictHostKeyChecking=no -o TCPKeepAlive=yes -o ServerAliveInterval=50 root@%s &" % (homeDir, keyName, address_to_tunnel[str(host)], address_to_tunnel[str(host)], swapped_ip)
       	 			debug("SHELL CMD: " + sshcmd)
				retry_cnt = 0
                                while ((retcode == 1) or (retry_cnt < 6)):
                                        retcode = subprocess.call(sshcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
                                        if retcode:
                                                warning("Failed to configure sshd_config on %s (tun%s). Retrying..." % (swapped_ip,address_to_tunnel[str(host)]))
                                                retry_cnt = retry_cnt + 1
						time.sleep(1+int(retry_cnt))
                                        else:
                                                retry_cnt = 6 # probably a better way to do this
                                        if retry_cnt == 5:
                                                error("Giving up...")
						cleanup("foo", "bar")
	
		        	# Provision interface
       		 		sshcmd = "ssh -i %s/.ssh/%s.pem -o StrictHostKeyChecking=no ubuntu@%s 'sudo ifconfig tun%s 10.%s.254.1 netmask 255.255.255.252'" % (homeDir, keyName, swapped_ip, address_to_tunnel[str(host)], address_to_tunnel[str(host)])
        			debug("SHELL CMD: " + sshcmd)
				retry_cnt = 0
				while ((retcode == 1) or (retry_cnt < 6)):
					retcode = subprocess.call(sshcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
					if retcode:
               		 			warning("Failed to assign interface address on %s (tun%s). Retrying..." % (swapped_ip,address_to_tunnel[str(host)]))
						retry_cnt = retry_cnt + 1
						time.sleep(1+int(retry_cnt))
					else:
						retry_cnt = 6 # probably a better way to do this
					if retry_cnt == 5:
						raw_input("Pausing to investigate")
						error("Giving up...")
						cleanup("foo", "bar")

			        ## Add return route back to us
			        sshcmd = "ssh -i %s/.ssh/%s.pem -o StrictHostKeyChecking=no ubuntu@%s 'sudo route add 10.%s.254.2 dev tun%s'" % (homeDir, keyName, swapped_ip, address_to_tunnel[str(host)], address_to_tunnel[str(host)])
			        debug("SHELL CMD: " + sshcmd)
				retry_cnt = 0
                                while ((retcode == 1) or (retry_cnt < 6)):
                                        retcode = subprocess.call(sshcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
                                        if retcode:
                                                warning("ERROR: Failed to add static route on %s (tun%s). Retrying..." % (swapped_ip,address_to_tunnel[str(host)]))
                                                retry_cnt = retry_cnt + 1
                                                time.sleep(1+int(retry_cnt))
                                        else:
                                                retry_cnt = 6 # probably a better way to do this
                                        if retry_cnt == 5:
                                                error("Giving up...")
						cleanup("foo", "bar")
				
	
				# Turn up our interface
			        os.system("ifconfig tun%s up" % address_to_tunnel[str(host)])
				debug("Turning up interface tun" + address_to_tunnel[str(host)])
	
				# Provision interface
			        os.system("ifconfig tun%s 10.%s.254.2 netmask 255.255.255.252" % (address_to_tunnel[str(host)], address_to_tunnel[str(host)]))
				debug("Assinging interface tun" + address_to_tunnel[str(host)] + " ip of 10." + address_to_tunnel[str(host)] + ".254.2")
				time.sleep(2)

			        # Adding local route (shoudlnt be needed)
			        debug("Adding static route 10." + address_to_tunnel[str(host)] + ".254.0/30 via dev tun" + address_to_tunnel[str(host)])
				route_cmd = 'ip route add 10.' + address_to_tunnel[str(host)] + '.254.0/30 via 0.0.0.0 dev tun' + address_to_tunnel[str(host)] + ' proto kernel scope link src 10.' + address_to_tunnel[str(host)] + '.254.2'
                                debug('SHELL CMD: ' + route_cmd)
                                os.system(route_cmd)
	
	       	 		# Allow connections to our proxy servers themselves
       		 		os.system("iptables -t nat -I POSTROUTING -d %s -j RETURN" % swapped_ip)
       	 
				# Nat outbound traffic going through our tunnels
        			os.system("iptables -t nat -A POSTROUTING -o tun%s -j MASQUERADE " % address_to_tunnel[str(host)])
	
				# Rebuild Route table
				route_interface = 0
				nexthopcmd = "ip route replace default scope global "
				weight = 1
       	  	                while route_interface < args.num_of_instances:
       	         	       		nexthopcmd = nexthopcmd + "nexthop via 10." + str(route_interface) + ".254.1 dev tun" + str(route_interface) + " weight " + str(weight) + " "
					route_interface = route_interface + 1

 	                       	debug("SHELL CMD: " + nexthopcmd)
                                retcode = subprocess.call(nexthopcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
                                if str(retcode) != "0":
                                        error("ERROR: Failed to install new route")
                                        debug("retcode: " + str(retcode))
                                        cleanup("foo", "bar")

				#os.system("%s" % nexthopcmd)       
 
				# Add static routes for our SSH tunnels
        			os.system("ip route add %s via %s dev %s > /dev/null 2>&1" % (swapped_ip, defaultgateway, args.interface))
				success("Replaced " + str(host) + " with " + str(swapped_ip) + " on tun" + address_to_tunnel[str(host)])
				
				# Removing from local dict
				address_to_tunnel[str(swapped_ip)] = address_to_tunnel[str(host)]
				del address_to_tunnel[str(host)]
				# print address_to_tunnel
				log(str(swapped_ip))
				# interface = interface + 1

#############################################################################################
# System and Program Arguments
#############################################################################################

parser = argparse.ArgumentParser()
parser.add_argument('-id', '--image-id', nargs='?', default='ami-d05e75b8', help="Amazon ami image ID.  Example: ami-d05e75b8. If not set, ami-d05e75b8.")
parser.add_argument('-t', '--image-type', nargs='?', default='t2.nano', help="Amazon ami image type Example: t2.nano. If not set, defaults to t2.nano.")
parser.add_argument('--region', nargs='?', default='us-east-1', help="Select the region: Example: us-east-1. If not set, defaults to us-east-1.")
parser.add_argument('-r', action='store_true', help="Enable Rotating AMI hosts.")
parser.add_argument('-v', action='store_true', help="Enable verbose logging. All cmd's should be printed to stdout")
parser.add_argument('num_of_instances', type=int, help="The number of amazon instances you'd like to launch.")
parser.add_argument('--name', nargs="?", help="Set the name of the instance in the cluster")
parser.add_argument('-i', '--interface', nargs='?', default='eth0', help="Interface to use, default is eth0")
parser.add_argument('-l', '--log', action='store_true', help="Enable logging of WAN IP's traffic is routed through. Output is to /tmp/")
args = parser.parse_args()

# system variables;
homeDir = os.getenv("HOME")
FNULL = open(os.devnull, 'w')
debug("Homedir: " + homeDir)
address_to_tunnel = {}

# Check for boto config
boto_config = homeDir + "/.boto"
if os.path.isfile(boto_config):
	for line in open(boto_config):
		pattern = re.findall("^aws_access_key_id = (.*)\n", line, re.DOTALL)
		if pattern:
			aws_access_key_id = pattern[0]	
		pattern = re.findall("^aws_secret_access_key = (.*)\n", line, re.DOTALL)
		if pattern:
			aws_secret_access_key = pattern[0]
else:
	debug("boto config file does not exist")
	aws_access_key_id = raw_input("What is the AWS Access Key Id: ")
	aws_secret_access_key = raw_input("What is the AWS Secret Access Key: ")

	boto_fh = open(boto_config, 'w+')
	boto_fh.write('[default]')
	boto_fh.write("\n")
	boto_fh.write('aws_access_key_id = ')
	boto_fh.write(aws_access_key_id)
	boto_fh.write("\n")
	boto_fh.write('aws_secret_access_key = ')
	boto_fh.write(aws_secret_access_key)
	boto_fh.write("\n")
	boto_fh.close

debug("AWS_ACCESS_KEY_ID: " + aws_access_key_id)
debug("AWS_SECRET_ACCESS_KEY: " + aws_secret_access_key)

# Generate sshkeyname
if args.name:

	# SSH Key Name
	keyName = "PC_" + args.name
	
	# AMI Security Group Name
	securityGroup = "PC_" + args.name
	
	# AMI Tag Name
	nameTag = "PC_" + args.name

	# iptables Name 
	iptablesName = "PC_" + args.name

	# log name
	logName = "PC_"  + args.name + ".log"

else:
	pid = os.getpid()
	stamp = time.time()
	m = hashlib.md5()
	tempstring = str(pid + stamp)
	m.update(tempstring)
	
	# SSH key Name
	keyName = "PC_" + m.hexdigest()

	# AMI Security Group Name
	securityGroup = "PC_" + m.hexdigest()

	# AMI Tag Name
	nameTag = "PC_" + m.hexdigest()

	# iptables Name
	iptablesName = "PC_" + m.hexdigest()

	# Log Name
	logName = "PC_" + m.hexdigest() + ".log"

# Get Interface IP
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

# Get Default Route
def get_default_gateway_linux():
    # Read the default gateway directly from /proc.
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue

            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

localIP = get_ip_address(args.interface)
debug("Local Interface IP for " + args.interface + ": " + localIP)

defaultgateway = get_default_gateway_linux()
debug("IP address of default gateway: " + defaultgateway)

debug("Opening logfile: /tmp/" + logName)
log("Proxy Cannon Started.")

# Define SigTerm Handler
signal.signal(signal.SIGINT, cleanup)

#############################################################################################
# Sanity Checks
#############################################################################################

# Check if running as root
if os.geteuid() != 0:
	error("You need to have root privileges to run this script.")
	exit()

# Check for required programs
# iptables
if not os.path.isfile("/sbin/iptables-save"):
	error("Could not find /sbin/iptables-save")
	exit()
if not os.path.isfile("/sbin/iptables-restore"):
	error("Could not find /sbin/iptables-restore")
	exit()
if not os.path.isfile("/sbin/iptables"):
	error("Could not find /sbin/iptables")
	exit()

# Check args
if args.num_of_instances < 1:
	error("You need at least 1 instance")
	exit();
elif args.num_of_instances > 20:
	warning("Woah there stallion, that's alot of instances, hope you got that sweet license from Amazon.")

# Display Warning
print "\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
print "+ This script will clear out any existing iptable and routing rules. +"
print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
warning("Would you like to continue y/[N]: ")
confirm = raw_input()
if confirm.lower() != "y":
	exit("Yeah you're right its probably better to play it safe.")

#############################################################################################
# System and Program Arguments
#############################################################################################

# Initialize connection to EC2
success("Connecting to Amazon's EC2...")
try:
	conn = boto.ec2.connect_to_region(region_name=args.region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
	#conn =  boto.ec2.connect_to_region(region_name=args.region)
except Exception as e:
	error("Failed to connect to Amazon EC2 because: %s" % e)
	exit()

# Generate KeyPair
success("Generating ssh keypairs...")
keypair = conn.create_key_pair(keyName)
keypair.save("%s/.ssh" % homeDir)
debug("SSH Key Pair Name " + keyName)
time.sleep(5)
success("Generating Amazon Security Group...")
try:
	sg = conn.create_security_group(name=securityGroup, description="Used for proxyCannon")
except Exception as e:
	error("Generating Amazon Security Group failed because: %s" % e)
	exit()

time.sleep(5)
try:
	sg.authorize(ip_protocol="tcp", from_port=22, to_port=22, cidr_ip="0.0.0.0/0")
except Exception as e:
        error("Generating Amazon Security Group failed because: %s" % e)
        exit()

debug("Security Group Name: " + securityGroup)

# Launch Amazon Instances
try:
	reservations = conn.run_instances(args.image_id, key_name=keyName, min_count=args.num_of_instances, max_count=args.num_of_instances, instance_type=args.image_type, security_groups=[securityGroup])
except Exception as e:
	error("Failed to start new instance: %s" % e)
	cleanup("null", "null")
warning("Starting %s instances, please give about 4 minutes for them to fully boot" % args.num_of_instances)

#sleep for 4 minutes while booting images
for i in range(21):
    sys.stdout.write('\r')
    sys.stdout.write("[%-20s] %d%%" % ('='*i, 5*i))
    sys.stdout.flush()
    time.sleep(11.5)
print "\n"
# Add tag name to instance for better management
for instance in reservations.instances:
	instance.add_tag("Name", nameTag)
debug("Tag Name: " + nameTag)

# Grab list of public IP's assigned to instances that were launched
allInstances = []
reservations = conn.get_all_instances(filters={"tag:Name" : nameTag, "instance-state-name" : "running"})
for reservation in reservations:
	for instance in reservation.instances:
		if instance.ip_address not in allInstances:
			if (instance.ip_address):
				allInstances.append(instance.ip_address)
debug("Public IP's for all instances: " + str(allInstances))

interface = 0
# Create ssh Tunnels for socks proxying
success("Provisioning Hosts.....")
for host in allInstances:

	log(host)	

	# Enable Tunneling on the remote host
	sshcmd = "ssh -i %s/.ssh/%s.pem -o StrictHostKeyChecking=no ubuntu@%s 'echo PermitTunnel yes | sudo tee -a  /etc/ssh/sshd_config'" % (homeDir, keyName, host)
	debug("SHELL CMD: " + sshcmd)

	retry_cnt = 0
	retcode = 0
	while ((retcode == 1) or (retry_cnt < 6)):
        	retcode = subprocess.call(sshcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
                if retcode:
                	warning("Failed to configure remote sshd_config on  %s to allow tunneling. Retrying..." % host)
                        retry_cnt = retry_cnt + 1
                        time.sleep(1)
                else:
                        retry_cnt = 6 # probably a better way to do this
                if retry_cnt == 5:
			error("Giving up...")
                	cleanup("foo", "bar")
	
	# Permit Root Logon
        sshcmd = "ssh -i %s/.ssh/%s.pem -o StrictHostKeyChecking=no ubuntu@%s 'sudo sed -i \"s/PermitRootLogin without-password/PermitRootLogin yes/\" /etc/ssh/sshd_config'" % (homeDir, keyName, host)
        debug("SHELL CMD: " + sshcmd)
        retry_cnt = 0
        while ((retcode == 1) or (retry_cnt < 6)): 
                retcode = subprocess.call(sshcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
                if retcode:
                        warning("Failed to configure remote sshd_config on %s to allow SSH Keys as root. Retrying..." % host)
                        retry_cnt = retry_cnt + 1
                        time.sleep(1)
                else:
                        retry_cnt = 6 # probably a better way to do this
                if retry_cnt == 5:
			error("Giving up...")
                        cleanup("foo", "bar")

        # Copy Keys 
        sshcmd = "ssh -i %s/.ssh/%s.pem -o StrictHostKeyChecking=no ubuntu@%s 'sudo cp /home/ubuntu/.ssh/authorized_keys /root/.ssh/'" %(homeDir, keyName, host)
        debug("SHELL CMD: " + sshcmd)
        retry_cnt = 0
        while ((retcode == 1) or (retry_cnt < 6)): 
                retcode = subprocess.call(sshcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
                if retcode:
                       	warning("ERROR: Failed to set authorized ssh keys on %s. Retrying..." % host)
                        retry_cnt = retry_cnt + 1
                        time.sleep(1)
                else:
                        retry_cnt = 6 # probably a better way to do this
                if retry_cnt == 5:
			error("Giving up...")
                        cleanup("foo", "bar")

	# Restarting Service to take new config (you'd think a simple reload would be enough)
	sshcmd = "ssh -i %s/.ssh/%s.pem -o StrictHostKeyChecking=no ubuntu@%s 'sudo service ssh restart'" % (homeDir, keyName, host)
	debug("SHELL CMD: " + sshcmd)
        retry_cnt = 0
        while ((retcode == 1) or (retry_cnt < 6)): 
                retcode = subprocess.call(sshcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
                if retcode:
                        warning("ERROR: Failed to restart sshd service on %s. Retrying..." % host)
                        retry_cnt = retry_cnt + 1
                        time.sleep(1)
                else:
                        retry_cnt = 6 # probably a better way to do this
                if retry_cnt == 5:
			error("Giving up...")
                        cleanup("foo", "bar")	
	
	# Establish tunnel interface
	sshcmd = "ssh -i %s/.ssh/%s.pem -w %s:%s -o StrictHostKeyChecking=no -o TCPKeepAlive=yes -o ServerAliveInterval=50 root@%s &" % (homeDir, keyName, interface, interface, host)
	debug("SHELL CMD: " + sshcmd)
        retry_cnt = 0
        while ((retcode == 1) or (retry_cnt < 6)): 
                retcode = subprocess.call(sshcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
                if retcode:
                        warning("Failed to establish ssh tuennl on %s. Retrying..." % host)
                        retry_cnt = retry_cnt + 1
                        time.sleep(1)
                else:
                        retry_cnt = 6 # probably a better way to do this
                if retry_cnt == 5:
			error("Giving up...")
                        cleanup("foo", "bar")	

	# Provision interface
	sshcmd = "ssh -i %s/.ssh/%s.pem -o StrictHostKeyChecking=no ubuntu@%s 'sudo ifconfig tun%s 10.%s.254.1 netmask 255.255.255.252'" % (homeDir, keyName, host, interface, interface)
        debug("SHELL CMD: " + sshcmd)
        retry_cnt = 0
        while ((retcode == 1) or (retry_cnt < 6)): 
                retcode = subprocess.call(sshcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
                if retcode:
                        warning("Failed to provision remote interface on %s. Retrying..." % host)
                        retry_cnt = retry_cnt + 1
                        time.sleep(1)
                else:
                        retry_cnt = 6 # probably a better way to do this
                if retry_cnt == 5:
			error("Giving up...")
                        cleanup("foo", "bar")
	
	# Enable forwarding on remote host
	sshcmd = "ssh -i %s/.ssh/%s.pem -o StrictHostKeyChecking=no ubuntu@%s 'sudo su root -c \"echo 1 > /proc/sys/net/ipv4/ip_forward\"'" % (homeDir, keyName, host)
        debug("SHELL CMD: " + sshcmd)
        retry_cnt = 0
        while ((retcode == 1) or (retry_cnt < 6)): 
                retcode = subprocess.call(sshcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
                if retcode:
                        warning("Failed to enable forwarding on %s. Retrying..." % host)
                        retry_cnt = retry_cnt + 1
                        time.sleep(1)
                else:
                        retry_cnt = 6 # probably a better way to do this
                if retry_cnt == 5:
			error("Giving up...")
                        cleanup("foo", "bar")
	
	# Provision iptables on remote host
	sshcmd = "ssh -i %s/.ssh/%s.pem -o StrictHostKeyChecking=no ubuntu@%s 'sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE'" % (homeDir, keyName, host)
        debug("SHELL CMD: " + sshcmd)
        retry_cnt = 0
        while ((retcode == 1) or (retry_cnt < 6)): 
                retcode = subprocess.call(sshcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
                if retcode:
                        warning("Failed to provision iptables on %s. Retrying..." % host)
                        retry_cnt = retry_cnt + 1
                        time.sleep(1)
                else:
                        retry_cnt = 6 # probably a better way to do this
                if retry_cnt == 5:
			error("Giving up...")
                        cleanup("foo", "bar")
	
	# Add return route back to us
	sshcmd = "ssh -i %s/.ssh/%s.pem -o StrictHostKeyChecking=no ubuntu@%s 'sudo route add 10.%s.254.2 dev tun%s'" % (homeDir, keyName, host, interface, interface)
        debug("SHELL CMD: " + sshcmd)
        retry_cnt = 0
        while ((retcode == 1) or (retry_cnt < 6)): 
                retcode = subprocess.call(sshcmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
                if retcode:
                        warning("Failed to provision static route  on %s. Retrying..." % host)
                        retry_cnt = retry_cnt + 1
                        time.sleep(1)
                else:
                        retry_cnt = 6 # probably a better way to do this
                if retry_cnt == 5:
			error("Giving up...")
                        cleanup("foo", "bar")
	
	# Turn up our interface
	os.system("ifconfig tun%s up" % interface)
	debug("Turning up interface tun" + str(interface))	

	# Provision interface
	os.system("ifconfig tun%s 10.%s.254.2 netmask 255.255.255.252" % (interface, interface))
	debug("Assinging interface tun" + str(interface) + " ip of 10." + str(interface) + ".254.2")
        time.sleep(2)

        # Adding local route (shoudlnt be needed)
        debug("Adding static route 10." + str(interface) + ".254.0/30 via dev tun" + str(interface))
        route_cmd = 'ip route add 10.' + str(interface) + '.254.0/30 via 0.0.0.0 dev tun' + str(interface) + ' proto kernel scope link src 10.' + str(interface) + '.254.2'
        debug('SHELL CMD: ' + route_cmd)
        os.system(route_cmd)

	interface = interface +1

	# add entry to table
	address_to_tunnel[str(host)] = str(interface-1)

# setup local forwarding
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
debug("SHELL CMD: ehco 1 > /proc/sys/net/ipv4/ip_forward")

# Save iptables
success("Saving existing iptables state")
os.system("/sbin/iptables-save > /tmp/%s" % iptablesName)

# Create iptables rule
# Flush existing rules
success("Building new iptables...")
os.system("iptables -t nat -F")
os.system("iptables -t mangle -F")
os.system("iptables -F")

count = args.num_of_instances
interface = 1;
nexthopcmd = "ip route add default scope global "

# Allow connections to RFC1918
os.system("iptables -t nat -I POSTROUTING -d 192.168.0.0/16 -j RETURN")
os.system("iptables -t nat -I POSTROUTING -d 172.16.0.0/16 -j RETURN")
os.system("iptables -t nat -I POSTROUTING -d 10.0.0.0/8 -j RETURN")

for host in allInstances:
	# Allow connections to our proxy servers themselves
	os.system("iptables -t nat -I POSTROUTING -d %s -j RETURN" % host)
	debug("SHELL CMD: iptables -t nat -I POSTROUTING -d " + host + " -j RETURN")
	# Nat outbound traffic going through our tunnels
	os.system("iptables -t nat -A POSTROUTING -o tun%s -j MASQUERADE " % (interface-1))
	debug("SHELL CMD: iptables -t nat -A POSTROUTING -o tun" + str(interface-1) + " -j MASQUERADE")
	# Build round robin route table command
	nexthopcmd = nexthopcmd + "nexthop via 10." + str(interface-1) + ".254.1 dev tun" + str(interface -1) + " weight 1 "
	# Add static routes for our SSH tunnels
	os.system("ip route add %s via %s dev %s" % (host, defaultgateway, args.interface))
	debug("SHELL CMD: ip route add " + host + " via " + defaultgateway + " dev " + args.interface)
	interface = interface + 1
	count = count - 1

# Allow RFC 1918 routes
os.system("ip route add 192.168.0.0/16 via %s dev %s > /dev/null 2>&1" % (defaultgateway, args.interface))
os.system("ip route add 172.16.0.0/16 via %s dev %s > /dev/null 2>&1" % (defaultgateway, args.interface))
os.system("ip route add 10.0.0.0/8 via %s dev %s > /dev/null 2>&1" % (defaultgateway, args.interface))

# Replace with our own new default route
os.system("%s" % nexthopcmd)
debug("SHELL CMD: " + nexthopcmd)

success("Done!")
print "\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
print "+ Leave this terminal open and start another to run your commands.   +"
print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
if args.r:
	print "[" + bcolors.WARNING + "~" + bcolors.ENDC +"] Press " + bcolors.BOLD + "ctrl + c" + bcolors.ENDC + " to terminate the script gracefully."
	success("Rotating IPs.")
	rotate_hosts()
else:
	print "[" + bcolors.WARNING + "~" + bcolors.ENDC +"] Press " + bcolors.BOLD + "ctrl + c" + bcolors.ENDC + " to terminate the script gracefully."
while 1:
	null = raw_input()
