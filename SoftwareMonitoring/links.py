#!/usr/bin/env python
'''
    Links of public blacklist
'''

LINKS = [
    # TOR IP list
    ('http://torstatus.blutmagie.de/ip_list_exit.php/Tor_ip_list_EXIT.csv', 'TOR'),

    # General 10days Blacklist IPs
    ('http://myip.ms/files/blacklist/general/latest_blacklist.txt', 'General'),

    # EmergingThreats
    ('http://rules.emergingthreats.net/blockrules/compromised-ips.txt', 'EmergingThreats'),

    # AlienVault
    ('http://reputation.alienvault.com/reputation.data',
     'AlienVault'),

    # BlocklistDE
    ('http://www.blocklist.de/lists/bruteforcelogin.txt',
     'BlocklistDE'),

    # Dragon Research Group - SSH
    ('http://dragonresearchgroup.org/insight/sshpwauth.txt',
     'Dragon'),

    # Dragon Research Group - VNC
    ('http://dragonresearchgroup.org/insight/vncprobe.txt',
     'Dragon2'),

    # OpenBLock
    ('http://www.openbl.org/lists/date_all.txt',
     'OpenBLock'),

    # NoThinkMalware
    ('http://www.nothink.org/blacklist/blacklist_malware_http.txt',
     'NoThinkMalware'),

    # NoThinkSSH
    ('http://www.nothink.org/blacklist/blacklist_ssh_all.txt',
     'NoThinkSSH'),

    # Feodo
    ('http://rules.emergingthreats.net/blockrules/compromised-ips.txt',
     'Feodo'),

    # antispam.imp.ch
    ('http://antispam.imp.ch/spamlist',
     'antispam.imp.ch'),

    # dshield
    ('http://www.dshield.org/ipsascii.html?limit=10000',
     'dshield'),

    # malc0de
    ('http://malc0de.com/bl/IP_Blacklist.txt',
     'malc0de'),

    # MalWareBytes
    ('http://hosts-file.net/rss.asp',
     'MalWareBytes')
]