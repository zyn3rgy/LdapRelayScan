#!/bin/bash

# Check if PROXY_CONFIG is set, if so, add it to the proxychains config
# and run the script with proxychains
if [ ! -z "$PROXY_CONFIG" ]; then
    
    #remove last two lines from original proxychains config
    sed -i '$d;N;$d' /etc/proxychains4.conf
    echo "$PROXY_CONFIG" >> /etc/proxychains4.conf
    proxychains4 -f /etc/proxychains4.conf python3 /LdapRelayScan//LdapRelayScan.py "$@"

# Otherwise, run the script without proxychains
else
    python3 /LdapRelayScan//LdapRelayScan.py "$@"
fi



