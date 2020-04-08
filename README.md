# paloalto-edl-agent
An external dynamic ip address list service for Palo Alto firewalls (EDL)

# About

This is an experimental project I've created that automatically updates and hosts external dynamic lists of malicious addresses collected from a Palo Alto firewall threat log.
The main requirement is that the firewall devices are configured to filter threat logs and forward specific security events to the ELD service.
The EDL service compiles a list of sources that are shared among firewalls in your estate and help to enforce the security policy and shun the attackers.

## PaloAlto firewall configuration

1). Configure HTTP server profile for forwarding logs  
```
Address: x.x.x.x
Protocol: http
Port: 8080
HTTP method: POST
Login Credential details (LASTPASS)
```

Payload details:
```
URI: /jobs/threat_update_source
HTTP Headers: Headers:content-type, value: application/json
Payload: { "timestamp": "$time_received", "reporter_ip": "$device_name", "attacker_ip": "$src", "victim_ip": "$dst", "threat": "$threatid", "threat_category": "$thr_category", "src_loc": " $srcloc" }
```
![GitHub Logo](/screenshots/http-profile-1.png)
Format: ![Alt Text](url)

2)Configure log forwarding profile with forwarding method to use HTTP server profile above, then attach it to any relevant security rule to forward logs to the EDL service.

Example of configuration
```
DMZ - Spyware - ALL, LOG Type: Threat, Filter: ( zone.src eq DMZ_Untrust ) and ( zone.dst eq DMZ_Trust )  and ( subtype eq spyware ) 
DMZ - Vulnerability - unknown-udp - ALL, LOG Type: Threat, Filter: ( zone.src eq DMZ_Untrust ) and ( zone.dst eq DMZ_Trust )  and ( subtype eq vulnerability ) and ( action neq alert ) and  ( app eq unknown-udp )
DMZ - Vulnerability - unknown-tcp - ALL, LOG Type: Threat, Filter: ( zone.src eq DMZ_Untrust ) and ( zone.dst eq DMZ_Trust )  and ( subtype eq vulnerability ) and ( action neq alert ) and  ( app eq unknown-tcp )
DMZ - Vulnerability - Web-browsing - Critical, LOG Type: Threat, Filter: ( zone.src eq DMZ_Untrust ) and ( zone.dst eq DMZ_Trust )  and ( subtype eq vulnerability ) and ( action neq alert ) and  ( app eq web-browsing )  and ( severity eq critical )
DMZ - Vulnerability - Web-browsing - High, LOG Type: Threat, Filter: ( zone.src eq DMZ_Untrust ) and ( zone.dst eq DMZ_Trust )  and ( subtype eq vulnerability ) and ( action neq alert ) and  ( app eq web-browsing )  and ( severity eq High )
```

