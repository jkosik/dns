#!/usr/bin/python3

#README:
#./validate.py ssh www.juraj.sk
#update cmd_dig to select DNS resolver. Can be also local unbound server

import sys
import subprocess
import getpass

#kontrola poctu cmd argumentov
if len(sys.argv) != 3:
    print("Syntax error. Usage: ./dnssec-validator.py [protocol] [domain]")
    print("E.g. ./dnssec-validator.py ssh www.juraj.sk")
    sys.exit()
else: pass

#sys.argv[2] = fqdn 
#cmd_status - existuje domena?
cmd_status = "dig +dnssec @195.91.0.17 " + sys.argv[2] + " | grep status"
p = subprocess.Popen(cmd_status, shell=True, stdout=subprocess.PIPE)
out = str(p.communicate()[0])
if not 'NOERROR' in out:
    print("You are trying NX domain or we have other issue :)")
    sys.exit()
else: pass

#cmd_dig grepuje relevantne flagy z hlavicky DNS odpovede.
#mozes pouzit aj lokalny unbound server na kontrolu domeny
cmd_dig = "dig +dnssec @195.91.0.17 " + sys.argv[2] + " |grep \";; flags\""
#cmd_dig = "dig +dnssec @127.0.0.1 " + sys.argv[2] + " | grep \";; flags\""

#spustenie cmd_dig a ulozenie do out
p = subprocess.Popen(cmd_dig, shell=True, stdout=subprocess.PIPE)
out = str(p.communicate()[0])

#cmd_user je command, ktory pozadauje spustit user
cmd_user = str(sys.argv[1] + " " + sys.argv[2])
print(cmd_user)

#"ad" (Authentic Data) flag urcuje, ze domena je podpisana
#ak domena podpisana...
if 'ad' in out:
    print("OK. Domain is signed and approved. Connecting...")
    print("Using current user \"" + getpass.getuser() + "\" or different one? [y/user]")
    user = input()
    if 'y' in user:
        p2 = subprocess.call(cmd_user, shell=True)
    else: 
        cmd_user = str(sys.argv[1] + " -l " + user + " " + sys.argv[2])
        p2 = subprocess.call(cmd_user, shell=True) 
#ak domena nepodpisana...
else:
    print("Domain not signed. Want to continue anyway? [y/n]")
    ok = input()
    if 'y' in ok:
        print("Using current user \"" + getpass.getuser() + "\" or different one? [y/user]")
        user = input()
        if 'y' in user:
            p3 = subprocess.call(cmd_user, shell=True)
        else:
            cmd_user = str(sys.argv[1] + " -l " + user + " " + sys.argv[2])
            p3 = subprocess.call(cmd_user, shell=True)
    else: sys.exit()






