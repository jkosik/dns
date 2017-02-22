#!/usr/bin/python3
'''
Identify open DNS resolver from the list of candidates.
Digs are sent to the individual addresses asking for NX domain of the domain under my control.
Run script multiple times to avoid lost packets (e.g. anti-DoS solutions).
Script can be used for testing RRL (Response Rate Limiting)
'''

import subprocess
import base64
import time
import random
import string
import sys

'''Create random string where length=dlz'''
def gen_str(dlz):        
	rand_str = ""
	for i in range (dlz):
		rand_char = random.choice(string.ascii_lowercase)
		rand_str += ''.join(rand_char)
	return (rand_str)

line = 0
line_count = 0
try:
	input_file = sys.argv[1]
except:
	print("Did you pass the input file?")
	sys.exit("Some error...")

'''Count lines in input file.Input file contains IPs of potential open DNS resolvers'''

with open(input_file, "r") as filey:
	for i in filey:
		line_count += 1

'''Send DNS queries to potential DNS resolvers'''
with open(input_file, "r") as filex:
	for i in filex:
		line += 1
		'''read IP from the list of potential open DNS resolvers'''
		ip = i.rstrip() 
		'''base64 encoding generates camelcase. Uppercase may be lost on the way, thus disabling correct decoding. Prefer ascii to hex encoding or none.
		'''		
#		ip_based64 = base64.b64encode(ip.encode("utf-8"))
		target = "@" + ip
		'''Add counter and random string to avoid caching'''
		domain = str(ip) + ".juraj." + gen_str(10) + str(line) + ".existing-dom.sk"
		print(ip, "\n", target, domain)
		subprocess.call(["dig", target, "+retry=0", domain])
		print ("Finished ", line ,"/", line_count)
		time.sleep(2)	#to avoid anti-DoS thresholds. Makes runtime a bit longer.
