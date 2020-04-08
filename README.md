# paloalto-edl-agent
An external dynamic ip address list service for Palo Alto firewalls (EDL)

ABOUT
This is an experimental project I've created that automatically updates and hosts external dynamic lists of malicious addresses. collected from a Palo Alto firewall threat log.
The main requirement is that the firewall devices are configured to filter threat logs and forward specific security events to the ELD service.
The EDL service compiles a list of sources that are shared among firewalls in your estate and help to enforce the security policy and shun the attackers.

