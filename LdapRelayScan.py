import dns.resolver
import ldap3
import argparse
import sys
import ssl
import socket
import getpass


class CheckLdaps:
    def __init__(self, nameserver, username, cmdLineOptions):
        self.options = cmdLineOptions
        self.__nameserver = nameserver
        self.__username = username

#Conduct a bind to LDAPS and determine if channel
#binding is enforced based on the contents of potential
#errors returned. This can be determined unauthenticated,
#because the error indicating channel binding enforcement
#will be returned regardless of a successful LDAPS bind.
def run_ldaps(inputUser, inputPassword, dcTarget):
    try:
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        ldapServer = ldap3.Server(
            dcTarget, use_ssl=True, port=636, get_info=ldap3.ALL, tls=tls)
        ldapConn = ldap3.Connection(
            ldapServer, user=inputUser, password=inputPassword, authentication=ldap3.NTLM)
        if not ldapConn.bind():
            if "data 80090346" in str(ldapConn.result):
                return True #channel binding IS enforced
            elif "data 52e" in str(ldapConn.result):
                return False #channel binding not enforced
            else:
                print("UNEXPECTED ERROR: " + str(ldapConn.result))
        else:
            #LDAPS bind successful
            return False #because channel binding is not enforced
            exit()
    except Exception as e:
        print("\n   [!] "+ dcTarget+" -", str(e))
        print("        * Ensure DNS is resolving properly, and that you can reach LDAPS on this host")


#DNS query of an SRV record that should return
#a list of domain controllers.
def ResolveDCs(nameserverIp, fqdn):
    dcList = []
    DnsResolver = dns.resolver.Resolver()
    DnsResolver.nameservers = [nameserverIp]
    dcQuery = DnsResolver.resolve(
        "_ldap._tcp.dc._msdcs."+fqdn, 'SRV', tcp=True)
    testout = str(dcQuery.response).split("\n")
    for line in testout:
        if "IN A" in line:
            dcList.append(line.split(" ")[0].rstrip(line.split(" ")[0][-1]))
    return dcList

#Conduct an anonymous bind to the provided "nameserver"
#arg during execution. This should work even if LDAP
#server integrity checks are enforced. The FQDN of the
#internal domain will be parsed from the basic server
#info gathered from that anonymous bind.
def InternalDomainFromAnonymousLdap(nameserverIp):
    tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
    #ldapServer = ldap3.Server(dcTarget, use_ssl=True, port=636, get_info=ldap3.ALL, tls=tls)
    ldapServer = ldap3.Server(
        nameserverIp, use_ssl=False, port=389, get_info=ldap3.ALL)
    ldapConn = ldap3.Connection(ldapServer, authentication=ldap3.ANONYMOUS)
    ldapConn.bind()
    parsedServerInfo = str(ldapServer.info).split("\n")
    fqdn = ""
    for line in parsedServerInfo:
        if "$" in line:
            fqdn = line.strip().split(":")[0]
    return fqdn


#Domain Controllers do not have a certificate setup for
#LDAPS on port 636 by default. If this has not been setup,
#the TLS handshake will hang and you will not be able to 
#interact with LDAPS. The condition for the certificate
#existing as it should is either an error regarding 
#the fact that the certificate is self-signed, or
#no error at all. Any other "successful" edge cases
#not yet accounted for.
def DoesLdapsCompleteHandshake(dcIp):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.settimeout(5)
  ssl_sock = ssl.wrap_socket(s,
                            cert_reqs=ssl.CERT_OPTIONAL,
                            suppress_ragged_eofs=False,
                            do_handshake_on_connect=False)
  ssl_sock.connect((dcIp, 636))
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


#Conduct and LDAP bind and determine if server signing
#requirements are enforced based on potential errors
#during the bind attempt. 
def run_ldap(inputUser, inputPassword, dcTarget):
    try:
        ldapServer = ldap3.Server(
            dcTarget, use_ssl=False, port=389, get_info=ldap3.ALL)
        ldapConn = ldap3.Connection(
            ldapServer, user=inputUser, password=inputPassword, authentication=ldap3.NTLM)
        if not ldapConn.bind():
            if "stronger" in str(ldapConn.result):
                return True #because LDAP server signing requirements ARE enforced
            elif "data 52e" or "data 532" in str(ldapConn.result):
                print("[!!!] invalid credentials - aborting to prevent unnecessary authentication")
                exit()
            else:
                print("UNEXPECTED ERROR: " + str(ldapConn.result))
        else:
            #LDAPS bind successful
            return False #because LDAP server signing requirements are not enforced
            exit()
    except Exception as e:
        print("\n   [!] "+ dcTarget+" -", str(e))
        print("        * Ensure DNS is resolving properly, and that you can reach LDAPS on this host")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        add_help=True, description="Checks Domain Controllers for LDAP authentication protection."
                                    + " You can check for only LDAPS protections (channel binding), this is done unauthenticated. "
                                    + "Alternatively you can check for both LDAPS and LDAP (server signing) protections. This requires a successful LDAP bind.")
    parser.add_argument('-method', choices=['LDAPS','BOTH'], default='LDAPS', metavar="method", action='store',
                        help="LDAPS or BOTH - LDAPS checks for channel binding, BOTH checks for LDAP signing and LDAP channel binding [authentication required]")
    parser.add_argument('-dc-ip', required=True, action='store',
                        help='DNS Nameserver on network. Any DC\'s IPv4 address should work.')
    parser.add_argument('-u', default='guest', metavar='username',action='store',
                        help='Domain username value.')
    parser.add_argument('-p', default='defaultpass', metavar='password',action='store',
                        help='Domain username value.')
    parser.add_argument('-nthash', metavar='nthash',action='store',
                        help='NT hash of password')
    options = parser.parse_args()
    domainUser = options.u

    password = options.p

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    if options.dc_ip == None:
        print("-dc-ip is required")
        exit()
    if options.method == 'BOTH':
        if domainUser == 'guest':
            print("[i] Using BOTH method requires a username parameter")
            exit()
    if options.method == 'BOTH' and options.u != 'guest' and (options.p != 'defaultpass' or options.nthash != None):
        if options.p == 'defaultpass' and options.nthash != None:
            password = "aad3b435b51404eeaad3b435b51404ee:" + options.nthash
        elif options.p != 'defaultpass' and options.nthash == None:
            password = options.p
        else:
            print("Something incorrect while providing credential material options")

    if options.method =='BOTH' and options.p == 'defaultpass' and options.nthash == None:   
        password = getpass.getpass(prompt="Password: ")
    fqdn = InternalDomainFromAnonymousLdap(options.dc_ip)


    dcList = ResolveDCs(options.dc_ip, fqdn)
    print("\n~Domain Controllers identifed~")
    for dc in dcList:
        print("   " + dc)

    print("\n~Checking DCs for LDAP NTLM relay protections~")
    username = fqdn + "\\" + domainUser
    #print("VALUES AUTHING WITH:\nUser: "+domainUser+"\nPass: " +password + "\nDomain:  "+fqdn)
    for dc in dcList:
        print("   " + dc)
        if options.method == "BOTH":
            ldapIsProtected = run_ldap(username, password, dc)
            if ldapIsProtected == False:
                print("      [+] (LDAP) SERVER SIGNING REQUIREMENTS NOT ENFORCED! ")
            elif ldapIsProtected == True:
                print("      [-] (LDAP) Server enforcing signing requirements")
            else:
                print("Something bad happened during LDAP bind")
        if DoesLdapsCompleteHandshake(dc) == True:
            ldapsIsProtected = run_ldaps(username, password, dc)
            if ldapsIsProtected == False:
                print("      [+] (LDAPS) CHANNEL BINDING NOT REQUIRED! PARTY TIME!")
            elif ldapsIsProtected == True:
                print("      [-] (LDAPS) channel binding required, no fun allowed")
            else:
                print("\nSomething went wrong...")
                exit()
        elif DoesLdapsCompleteHandshake(dc) == False:
            print("      [!] "+dc+ " - cannot complete TLS handshake, cert likely not configured")
    print()
