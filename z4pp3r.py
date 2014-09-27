#!/user/bin/env python
import socket
import subprocess
import sys
from datetime import datetime

logo='''############################################################## 
#               d8888                     .d8888b.           #
#              d8P888                    d88P  Y88b          #
#             d8P 888                         .d88P          #
#  88888888  d8P  888  88888b.  88888b.      8888"  888d888  #
#     d88P  d88   888  888 "88b 888 "88b      "Y8b. 888P"    #
#    d88P   8888888888 888  888 888  888 888    888 888      #
#   d88P          888  888 d88P 888 d88P Y88b  d88P 888      #
#  88888888       888  88888P"  88888P"   "Y8888P"  888      #
#                      888      888                          #
#                      888      888                          #
#                      888      888                          #
#  					Remote Port Scanner  #
# 				Developed by: @H3XtheG0D     #
#			Contact: h3xtheg0d@gmail.com         #
##############################################################'''

blank =''' '''

#Clear Screen
subprocess.call('clear', shell=True)

#Print Logo
print logo
print blank

#Ask For Input
remoteServer   = raw_input("Enter a host name to scan: ")
remoteServerIP = socket.gethostbyname(remoteServer)

#Print Banner With Information On Host To Be Scanned
print "-" * 62
print "Please wait, scanning remote host", remoteServerIP
print "NOTE: This may take some time, scanning port range 21-1023!"
print "-" * 62

#Check Scan Start Time
t1 = datetime.now()

# Using the range function to specify ports (here it will scans all ports between 1 and 1024)

#Error Handling
try:
    for port in range(21,1023):  
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((remoteServerIP, port))
        if result == 0:
            print "Port {}: \t Open".format(port)
        sock.close()

except KeyboardInterrupt:
    print "You pressed Ctrl+C"
    sys.exit()

except socket.gaierror:
    print 'Hostname could not be resolved. Exiting'
    sys.exit()

except socket.error:
    print "Couldn't connect to server"
    sys.exit()
	
#Check Time Again
t2 = datetime.now()

#Calculate Difference In Start & Stop Times
total = t2 - t1

#Print Scan Information
print blank
print 'Scanning Completed In: ', total
