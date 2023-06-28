$TTL	604800
@	IN	SOA	steampowered.com. admin.steampowered.com. (
			      3		; Serial
			 604800		; Refresh
			  86400		; Retry
			2419200		; Expire
			 604800 )	; Negative Cache TTL
;

; name server - NS record
@	IN	NS	ns1.steampowered.com.

; name server - A record
ns1	IN	A	192.168.56.106

; 192.168.56.0/24 - A record
store	IN	A	192.168.56.103
