# Attacco di phishing con DNS poisoning

# Cos'è il DNS poisoning?

L'attacco **DNS poisoning** vuole inserire record fasulli in risposta a query DNS, con lo scopo di ingannare la vittima. Con il **phishing** si vuole portare la vittima ad un sito web fasullo, all'apparenza identico all'originale. L'attacco prevede che l'url associato al sito web presenti il dominio originale, non destando sospetti agli occhi della vittima.

# Utilizzo

## ARP spoofing
Il primo step prevede di realizzare un attacco MITM (Man in the middle) grazie all'ARP spoofing, tramite il comando:
~~~bash
$ sudo python3 arp_spoofing.py -g GATEWAY_IP -t TARGET_IP
~~~

~~~bash
usage: arp_poisoning.py [-h] [-g GATEWAY] [-t TARGET]

options:
- `-h`, `--help`: Show this help message and exit
- `-g GATEWAY`, `--gateway GATEWAY`: IP address of the gateway/DNS server
- `-t TARGET`, `--target TARGET`: IP address of the target
~~~


Verranno mandati pacchetti ARP alle due macchine indicate tra i parametri del comando. Dopo l'attacco:
- il *gateway* manderà all'attaccante il traffico verso il *target*; 
- il *target* manderà all'attaccante il traffico verso il *gateway*.

## DNS poisoning
Il secondo step prevede di modificare solo i pacchetti di tipo DNS Resource Record (DNS reply) verso *store.steampowered.com.* indirizzando il traffico verso l'indirizzo IP indicato.
~~~bash
$ sudo python3 dns_poisoning.py -i ATTACKER_IP
~~~

~~~bash
usage: dns_poisoning.py [-h] [-i IP]

options:
- `-h`, `--help`: Show this help message and exit
- `-i IP`, `--ip`: IP address to spoof
~~~

Dopo l'attacco, in seguito alla ricezione di un pacchetto DNS reply:
- se il pacchetto presenta nella qname *store.steampowered.com.*, nella risposta l'IP effettivo viene sostituito dall' *ATTACKER_IP* indicato; 
- altrimenti viene fatto il redirect senza modifiche.

