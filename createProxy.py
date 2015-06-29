#!/usr/bin/python
# Author: __int128 <@jarsnah12>
#######################
# Requirements:
#	boto:	pip install -U boto
#
#######################
# To Do
#	1) Script doesnt NEED to run as root but im lazy
#	2) Create Debug options
#
#######################
import boto.ec2
import os
import argparse
import time
import sys
import subprocess

# Parse user input
parser = argparse.ArgumentParser()
parser.add_argument("image_id", help="Amazon ami image ID.  Example: ami-d05e75b8")
parser.add_argument("image_type", help="Amazon ami image type Example: t2.micro")
parser.add_argument("num_of_instances", type=int, help="The number of amazon instances you'd like to launch")
parser.add_argument("region", help="Select the region: Example: us-east-1")
parser.add_argument("key_id", help="Amazon Access Key ID")
parser.add_argument("access_key", help="Amazon's Secret Key Access")
args = parser.parse_args()

# system variables;
homeDir = os.getenv("HOME")
startPort = int("9090") # starting port

# Initialize connection to EC2
try:
	conn = boto.ec2.connect_to_region(region_name=args.region, aws_access_key_id=args.key_id, aws_secret_access_key=args.access_key)
except Exception as e:
	print "Connection attempt failed because %s" % e
print "Connection successful!"

# Check to see if SSH KeyPair already exists
try:
	kp = conn.get_all_key_pairs(keynames="forProxy")
except:
	# pair does not exist, creating new key pair
	keypair = conn.create_key_pair("forProxy")
	keypair.save("%s/.ssh" % homeDir)

# Check to see if a security group already exists, if not create one
try:
	sg = conn.get_all_security_groups(groupnames="forProxy")	
except:
	# Security Group does not exist, creating new group
	sg = conn.create_security_group(name="forProxy", description="Used for Proxy servers")
	try:
		# Adding single ssh rule to allow access
		sg.authorize(ip_protocol="tcp", from_port=22, to_port=22, cidr_ip="0.0.0.0/0")
	except Exception as e:
		print "Generating rule for security group failed because %s" % e


# Launch Amazon Instances
reservations = conn.run_instances(args.image_id, key_name="forProxy", min_count=args.num_of_instances, max_count=args.num_of_instances, instance_type=args.image_type, security_groups=['forProxy'])
print "Starting instances, please give about 4 minutes for them to fully boot"

#sleep for 4 minutes while booting images
for i in range(21):
    sys.stdout.write('\r')
    sys.stdout.write("[%-20s] %d%%" % ('='*i, 5*i))
    sys.stdout.flush()
    time.sleep(11.5)
print "\n"

# Add tag name to instance for better management
for instance in reservations.instances:
	instance.add_tag("Name", "forProxy")

# Grab list of public IP's assigned to instances that were launched
allInstances = []
reservations = conn.get_all_instances(filters={"tag:Name" : "forProxy", "instance-state-name" : "running"})
for reservation in reservations:
	for instance in reservation.instances:
		if instance.ip_address not in allInstances:
			if (instance.ip_address):
				allInstances.append(instance.ip_address)

# Create ssh Tunnels for socks proxying
port = startPort
for host in allInstances:
	os.system("ssh -i %s/.ssh/forProxy.pem -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -g -f -N -D %s ubuntu@%s" % (homeDir, port, host))
	port = port + 1;

# Create Proxy List
config = open('/etc/proxychains.conf', 'w')
config.write("dynamic_chain\n")
config.write("random_chain\n")
config.write("chain_len = 1\n")
config.write("[ProxyList]\n")
port = startPort
for host in allInstances:
	config.write("socks5 127.0.0.1 %s\n" % port)
	port = port + 1;
config.close()

print "You're good to go!\n"
print "Now in another terminal run your proxychains command.  Example  \n$ proxychains nmap -sV -vv -PN scanme.nmap.org\n"

raw_input("Press Enter to terminate all proxy instances and clean up temp rules/keys ")

# Terminate instance
print "Terminating instances..."
for reservation in reservations:
	for instance in reservation.instances:
		instance.terminate()

print "Pausing for 30 seconds so instances can properly terminate before removing security groups"
time.sleep(30)

# Remove Security Groups
print "Deleting Security Groups..."
try:
	conn.delete_security_group(name="forProxy")
except Exception as e:
	print "Deletion of security group failed because %s" % e

# Remove Key Pairs
print "Removing KeyPairs"
try:
	conn.delete_key_pair(key_name='forProxy')
except Exception as e:
	print "Deletion of key pair failed because %s" % e

# Remove local files
print "Removing local config / key files"
subprocess.Popen("rm -f %s/.ssh/forProxy.pem" % homeDir, shell=True)
subprocess.Popen("rm -rf /etc/proxychains.conf", shell=True)


print "Done!"
