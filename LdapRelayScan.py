import dns.resolver
import ldap3
import argparse
import sys
import ssl
import socket
import getpass
import asyncio
from msldap.commons.url import MSLDAPURLDecoder, MSLDAPClientConnection


class CheckLdaps:
    def __init__(self, nameserver, username, cmd_line_options):
        self.options = cmd_line_options
        self.__nameserver = nameserver
        self.__username = username


# Conduct a bind to LDAPS and determine if channel
# binding is enforced based on the contents of potential
# errors returned. This can be determined unauthenticated,
# because the error indicating channel binding enforcement
# will be returned regardless of a successful LDAPS bind.
def run_ldaps_no_epa(input_user, input_password, dc_target):
    try:
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        ldap_server = ldap3.Server(
            dc_target, use_ssl=True, port=636, get_info=ldap3.ALL, tls=tls)
        ldap_conn = ldap3.Connection(
            ldap_server, user=input_user, password=input_password, authentication=ldap3.NTLM)
        if not ldap_conn.bind():
            if "data 80090346" in str(ldap_conn.result):
                return True  # channel binding IS enforced
            elif "data 52e" in str(ldap_conn.result):
                return False  # channel binding not enforced
            else:
                print("UNEXPECTED ERROR: " + str(ldap_conn.result))
        else:
            # LDAPS bind successful
            return False  # because channel binding is not enforced
    except Exception as e:
        print("\n   [!] " + dc_target + " -", str(e))
        print("        * Ensure DNS is resolving properly, and that you can reach LDAPS on this host")


# Conduct a bind to LDAPS with channel binding supported
# but intentionally miscalculated. In the case that and
# LDAPS bind has without channel binding supported has occured,
# you can determine whether the policy is set to "never" or
# if it's set to "when supported" based on the potential
# error recieved from the bind attempt.
async def run_ldaps_with_epa(input_user, input_password, dc_target):
    try:
        url = f'ldaps+ntlm-password://{input_user}:{input_password}@{dc_target}'
        conn_url = MSLDAPURLDecoder(url)
        ldaps_client = conn_url.get_client()
        ldaps_client_conn = MSLDAPClientConnection(ldaps_client.target, ldaps_client.creds)
        _, err = await ldaps_client_conn.connect()

        if err is not None:
            print("ERROR while connecting to " + dc_target + ": " + err)

        # forcing a miscalculation of the "Channel Bindings" av pair in Type 3 NTLM message
        ldaps_client_conn.cb_data = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
                                    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
                                    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
                                    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 '
        _, err = await ldaps_client_conn.bind()
        if "data 80090346" in str(err):
            return True
        elif "data 52e" in str(err):
            return False
        elif err is not None:
            print("ERROR while connecting to " + dc_target + ": " + err)
        elif err is None:
            return False
    except Exception as e:
        print("something went wrong during ldaps_withEPA bind:" + str(e))


# DNS query of an SRV record that should return
# a list of domain controllers.
def resolve_dcs(name_server_ip, fqdn):
    dc_list = []
    dns_resolver = dns.resolver.Resolver()
    dns_resolver.nameservers = [name_server_ip]
    dc_query = dns_resolver.resolve(
        "_ldap._tcp.dc._msdcs." + fqdn, 'SRV', tcp=True)
    testout = str(dc_query.response).split("\n")

    for line in testout:
        if "IN A" in line:
            dc_list.append(line.split(" ")[0].rstrip('.'))

    return dc_list


# Conduct an anonymous bind to the provided "nameserver"
# arg during execution. This should work even if LDAP
# server integrity checks are enforced. The FQDN of the
# internal domain will be parsed from the basic server
# info gathered from that anonymous bind.
def internal_domain_from_anonymous_ldap(name_server_ip):
    tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
    # ldapServer = ldap3.Server(dcTarget, use_ssl=True, port=636, get_info=ldap3.ALL, tls=tls)
    ldap_server = ldap3.Server(
        name_server_ip, use_ssl=False, port=389, get_info=ldap3.ALL)
    ldap_conn = ldap3.Connection(ldap_server, authentication=ldap3.ANONYMOUS)
    ldap_conn.bind()
    parsed_server_info = str(ldap_server.info).split("\n")
    fqdn = ""

    for line in parsed_server_info:
        if "$" in line:
            fqdn = line.strip().split(":")[0]

    return fqdn


# Domain Controllers do not have a certificate setup for
# LDAPS on port 636 by default. If this has not been setup,
# the TLS handshake will hang and you will not be able to 
# interact with LDAPS. The condition for the certificate
# existing as it should is either an error regarding 
# the fact that the certificate is self-signed, or
# no error at all. Any other "successful" edge cases
# not yet accounted for.
def does_ldaps_complete_handshake(dc_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    ssl_sock = ssl.wrap_socket(s,
                               cert_reqs=ssl.CERT_OPTIONAL,
                               suppress_ragged_eofs=False,
                               do_handshake_on_connect=False)
    ssl_sock.connect((dc_ip, 636))
    try:
        ssl_sock.do_handshake()
        ssl_sock.close()
        return True
    except Exception as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            ssl_sock.close()
            return True
        if "handshake operation timed out" in str(e):
            ssl_sock.close()
            return False
        else:
            print("Unexpected error during LDAPS handshake: " + e)
        ssl_sock.close()


# Conduct and LDAP bind and determine if server signing
# requirements are enforced based on potential errors
# during the bind attempt. 
def run_ldap(input_user, input_password, dc_target):
    try:
        ldap_server = ldap3.Server(
            dc_target, use_ssl=False, port=389, get_info=ldap3.ALL)
        ldap_conn = ldap3.Connection(
            ldap_server, user=input_user, password=input_password, authentication=ldap3.NTLM)
        if not ldap_conn.bind():
            if "stronger" in str(ldap_conn.result):
                return True  # because LDAP server signing requirements ARE enforced
            elif "data 52e" or "data 532" in str(ldap_conn.result):
                print("[!!!] invalid credentials - aborting to prevent unnecessary authentication")
                exit()
            else:
                print("UNEXPECTED ERROR: " + str(ldap_conn.result))
        else:
            # LDAPS bind successful
            return False  # because LDAP server signing requirements are not enforced
    except Exception as e:
        print("\n   [!] " + dc_target + " -", str(e))
        print("        * Ensure DNS is resolving properly, and that you can reach LDAPS on this host")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        add_help=True, description="Checks Domain Controllers for LDAP authentication protection."
                                   + "You can check for only LDAPS protections (channel binding), this is done "
                                     "unauthenticated. "
                                   + "Alternatively you can check for both LDAPS and LDAP (server signing) "
                                     "protections. This requires a successful LDAP bind.")
    parser.add_argument('-method', choices=['LDAPS', 'BOTH'], default='LDAPS', metavar="method", action='store',
                        help="LDAPS or BOTH - LDAPS checks for channel binding, BOTH checks for LDAP signing and LDAP "
                             "channel binding [authentication required]")
    parser.add_argument('-dc-ip', required=True, action='store',
                        help='DNS Nameserver on network. Any DC\'s IPv4 address should work.')
    parser.add_argument('-u', default='guest', metavar='username', action='store',
                        help='Domain username value.')
    parser.add_argument('-p', default='defaultpass', metavar='password', action='store',
                        help='Domain username value.')
    parser.add_argument('-nthash', metavar='nthash', action='store',
                        help='NT hash of password')
    options = parser.parse_args()
    domainUser = options.u

    password = options.p

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if options.dc_ip is None:
        print("-dc-ip is required")
        exit()
    if options.method == 'BOTH':
        if domainUser == 'guest':
            print("[i] Using BOTH method requires a username parameter")
            exit()
    if options.method == 'BOTH' and options.u != 'guest' and (options.p != 'defaultpass' or options.nthash is not None):
        if options.p == 'defaultpass' and options.nthash is not None:
            password = "aad3b435b51404eeaad3b435b51404ee:" + options.nthash
        elif options.p != 'defaultpass' and options.nthash is None:
            password = options.p
        else:
            print("Something incorrect while providing credential material options")

    if options.method == 'BOTH' and options.p == 'defaultpass' and options.nthash is None:
        password = getpass.getpass(prompt="Password: ")
    fqdn = internal_domain_from_anonymous_ldap(options.dc_ip)

    dcList = resolve_dcs(options.dc_ip, fqdn)
    print("\n~Domain Controllers identifed~")
    for dc in dcList:
        print("   " + dc)

    print("\n~Checking DCs for LDAP NTLM relay protections~")
    username = fqdn + "\\" + domainUser
    # print("VALUES AUTHING WITH:\nUser: "+domainUser+"\nPass: " +password + "\nDomain:  "+fqdn)

    for dc in dcList:
        print("   " + dc)
        if options.method == "BOTH":
            ldapIsProtected = run_ldap(username, password, dc)
            if not ldapIsProtected:
                print("      [+] (LDAP)  SERVER SIGNING REQUIREMENTS NOT ENFORCED! ")
            elif ldapIsProtected:
                print("      [-] (LDAP)  server enforcing signing requirements")
            else:
                print("Something bad happened during LDAP bind")
        if does_ldaps_complete_handshake(dc):
            ldapsChannelBindingAlwaysCheck = run_ldaps_no_epa(username, password, dc)
            ldapsChannelBindingWhenSupportedCheck = asyncio.run(run_ldaps_with_epa(username, password, dc, fqdn))
            if not ldapsChannelBindingAlwaysCheck and ldapsChannelBindingWhenSupportedCheck == True:
                print("      [-] (LDAPS) channel binding is set to \"when supported\" - this")
                print("                  may prevent an NTLM relay depending on the client's")
                print("                  support for channel binding.")
            elif not ldapsChannelBindingAlwaysCheck and not ldapsChannelBindingWhenSupportedCheck:
                print("      [+] (LDAPS) CHANNEL BINDING SET TO \"NEVER\"! PARTY TIME!")
            elif ldapsChannelBindingAlwaysCheck:
                print("      [-] (LDAPS) channel binding set to \"required\", no fun allowed")
            else:
                print("\nSomething went wrong...")
                print("For troubleshooting:\nldapsChannelBindingAlwaysCheck - " + str(
                    ldapsChannelBindingAlwaysCheck) + "\nldapsChannelBindingWhenSupportedCheck: " + str(
                    ldapsChannelBindingWhenSupportedCheck))
                exit()
            # print("For troubleshooting:\nldapsChannelBindingAlwaysCheck - " +str(
            # ldapsChannelBindingAlwaysCheck)+"\nldapsChannelBindingWhenSupportedCheck: "+str(
            # ldapsChannelBindingWhenSupportedCheck))

        elif not does_ldaps_complete_handshake(dc):
            print("      [!] " + dc + " - cannot complete TLS handshake, cert likely not configured")
    print()
