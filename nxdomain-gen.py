#!/usr/bin/python3

import random
import string
import subprocess
import threading

dig_ip="@xx.xx.xx.xx"
req_count=10
rr_type="A"
main_dom="yrome.eu"

'''Run dig cmd via defined DNS resolver @IP'''
def gen_nx_req():
		subprocess.call(["dig", dig_ip, "+retry=0", domain, rr_type, "+noauthority", "+nostats", "+noadditional"])

'''Create random string where length=dlz'''
def gen_str(dlz):        
	rand_str = ""
	for i in range (dlz):
		rand_char = random.choice(string.ascii_lowercase)
		rand_str += ''.join(rand_char)
	return (rand_str)

'''Create dom-list.txt: x.juraj.randomvalue.main_dom'''
order = 0
with open("dom-lst.txt", "w+") as filex:        #w+ rewrites file
	for i in range(req_count):
		order += 1	
		fulldomain = str(order) + ".juraj." + gen_str(15) + "." + main_dom + "\n" 
		filex.write(fulldomain)

'''run gen_nx_req in multiple threads, since digs normally wait until previous one finishes'''
with open("dom-lst.txt", "r") as filex:
	for i in filex:
		domain = i.rstrip() #CORRECT
		threading.Thread(target=gen_nx_req).start()

'''log all nxdomain responses'''
#tshark -R dns.flags.rcode==3 -s 1600 -i any -T fields -e ip.src -e ip.dst -e dns.qry.name
