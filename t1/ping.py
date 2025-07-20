import socket
  
#creates a new socket using the given address family.
socket_obj = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  
#setting up the default timeout in seconds for new socket object
socket.setdefaulttimeout(1)
addr = input("enter hostname: ")
ip_addr = socket.gethostbyname(addr)
port = int(input("Enter port number: "))
#returns 0 if connection succeeds else raises error
result = socket_obj.connect_ex((ip_addr,port)) #address and port in the tuple format
print(result)
#closes te object
socket_obj.close()