from socket import * 
from threading import *

def connScan(target_host,port):
	try:
		main_sock=socket(AF_INET,SOCK_STREAM) 
		main_sock.connect((target_host,port))
		print("\n [ALERT!] %d/tcp open" %port)
	except:
		print("no")

	finally:
		main_sock.close()



def PortScan(target_host,target_ports):

	# Resolving hostname by IP and IP by hostname
 
	try:
		target_IP=gethostbyname(target_host)
	except:
		print("Couldn't resolve host %d" %target_host)

	try:
		target_name = gethostbyaddr(target_IP)
		print("\n[+] Scan results For :" + target_name[0])
	except:
		print("\n[+]  Scan Results For : " +target_IP)

	setdefaulttimeout(1)
	for port in target_ports:
		t=Thread(target=connScan, args=(target_host,int(port)))  # Run a connsScan function to scan the ports
		t.start()


def main():



	target_host= str(input("Enter host name: "))
	target_ports= list(range(20, 1100)) # Number of ports to be scanned using range() *THIS CAN BE CHANGED 

	# Scanning of port

	PortScan(target_host,target_ports)

if __name__ == "__main__":
	main()