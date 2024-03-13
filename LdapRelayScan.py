import dns.resolver
import argparse
import sys
import ssl
import socket
import getpass
import asyncio
import copy
from msldap.connection import MSLDAPClientConnection
from msldap.commons.factory import LDAPConnectionFactory
from msldap.commons.target import MSLDAPTarget, UniProto
from asyauth.common.credentials import UniCredential, asyauthSecret, asyauthProtocol


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
async def run_ldaps_noEPA(cred, dcTarget, timeout = 10):
    try:
        target = MSLDAPTarget(dcTarget, 636, protocol=UniProto.CLIENT_SSL_TCP, timeout=timeout)
        connection = MSLDAPClientConnection(target, cred)
        connection._disable_channel_binding = True
        _, err = await connection.connect()
        if err is not None:
            raise err
        _, err = await connection.bind()
        if err is not None:
            if "data 80090346" in str(err):
                return True #channel binding IS enforced
            elif "data 52e" in str(err):
                return False #channel binding not enforced
            else:
                print("UNEXPECTED ERROR: " + str(err))
        else:
            #LDAPS bind successful
            return False #because channel binding is not enforced
        
    except Exception as e:
        print("\n   [!] "+ dcTarget+" -", str(e))
        print("        * Ensure DNS is resolving properly, and that you can reach LDAPS on this host")

#Conduct a bind to LDAPS with channel binding supported
#but intentionally miscalculated. In the case that and
#LDAPS bind has without channel binding supported has occured,
#you can determine whether the policy is set to "never" or
#if it's set to "when supported" based on the potential
#error recieved from the bind attempt.
async def run_ldaps_withEPA(cred, dcTarget, timeout = 10):
    try:
        target = MSLDAPTarget(dcTarget, 636, protocol=UniProto.CLIENT_SSL_TCP, timeout=timeout)
        ldapsClientConn = MSLDAPClientConnection(target, cred)
        #forcing a miscalculation of the "Channel Bindings" av pair in Type 3 NTLM message
        ldapsClientConn._null_channel_binding = True
        _, err = await ldapsClientConn.connect()
        if err is not None:
            raise err
        
        _, err = await ldapsClientConn.bind()
        if "data 80090346" in str(err):
            return True
        elif "data 52e" in str(err):
            return False
        elif err is not None:
            print("ERROR while connecting to " + dcTarget + ": " + err)
        elif err is None:
            return False

    except Exception as e:
        print("something went wrong during ldaps_withEPA bind:" + str(e))


#DNS query of an SRV record that should return
#a list of domain controllers.
def ResolveDCs(nameserverIp, fqdn):
    dcList = {}
    DnsResolver = dns.resolver.Resolver()
    DnsResolver.timeout = 20
    DnsResolver.nameservers = [nameserverIp]
    dcQuery = DnsResolver.resolve(
        "_ldap._tcp.dc._msdcs."+fqdn, 'SRV', tcp=True)
    testout = str(dcQuery.response).split("\n")
    for line in testout:
        if "IN A" in line:
            dcList[line.split(" ")[0].rstrip(line.split(" ")[0][-1])] = 1
    return list(dcList.keys())

#Conduct an anonymous bind to the provided "nameserver"
#arg during execution. This should work even if LDAP
#server integrity checks are enforced. The FQDN of the
#internal domain will be parsed from the basic server
#info gathered from that anonymous bind.
async def InternalDomainFromAnonymousLdap(nameserverIp, timeout = 10):
    try:
        cred = UniCredential("", username="", domain="", stype=asyauthSecret.NONE, protocol=asyauthProtocol.SIMPLE)
        target_plain = MSLDAPTarget(nameserverIp, 389, timeout=timeout)
        target_ssl = MSLDAPTarget(nameserverIp, 636, protocol = UniProto.CLIENT_SSL_TCP  ,timeout=timeout)
        for target in [target_plain, target_ssl]:
            ldapConn = MSLDAPClientConnection(target, cred)
            _, err = await ldapConn.connect()
            if err is not None:
                print('Connection failed using target: ' + str(target) + " - " + str(err))
                continue
            _, err = await ldapConn.bind()
            if err is not None:
                print('Bind failed using target: ' + str(target) + " - " + str(err))
                continue
            info, err = await ldapConn.get_serverinfo()
            if err is not None:
                print('Server info failed using target: ' + str(target) + " - " + str(err))
                continue
            print()
            fqdn = info.get('ldapServiceName', '').strip().split("@")[1]
            return fqdn
            
    except Exception as e:
        print("Could not connect to LDAP server. Error: " + str(e))
        exit()


#Domain Controllers do not have a certificate setup for
#LDAPS on port 636 by default. If this has not been setup,
#the TLS handshake will hang and you will not be able to 
#interact with LDAPS. The condition for the certificate
#existing as it should is either an error regarding 
#the fact that the certificate is self-signed, or
#no error at all. Any other "successful" edge cases
#not yet accounted for.
def DoesLdapsCompleteHandshake(dcIp, timeout = 5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ssl_sock = ctx.wrap_socket(
        s,
        suppress_ragged_eofs=False,
        do_handshake_on_connect=False
    )
    try:
        ssl_sock.connect((dcIp, 636))
    except Exception as e:
        print('Failed to connect to ' + dcIp + ' on port 636: ' + str(e))

    try:
        
        ssl_sock.do_handshake()
        ssl_sock.close()
        return True
    except Exception as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            return True
        if "handshake operation timed out" in str(e):
            return False
        else:
            print("Unexpected error during LDAPS handshake: " + str(e))
    finally:
        ssl_sock.close()


#Conduct and LDAP bind and determine if server signing
#requirements are enforced based on potential errors
#during the bind attempt.
async def run_ldap(cred, dcTarget, timeout = 5):
    try:
        target = MSLDAPTarget(dcTarget, 389, timeout=timeout)
        ldapsClientConn = MSLDAPClientConnection(target, cred)
        ldapsClientConn._disable_signing = True
        _, err = await ldapsClientConn.connect()
        if err is not None:
            raise err
        
        _, err = await ldapsClientConn.bind()
        if err is not None:
            errstr = str(err).lower()
            if "stronger" in errstr:
                return True #because LDAP server signing requirements ARE enforced
            elif "data 52e" in errstr or "data 532" in errstr:
                print("[!!!] invalid credentials - aborting to prevent unnecessary authentication")
                exit()
            else:
                print("UNEXPECTED ERROR: " + str(err))
        else:
            #LDAPS bind successful
            return False #because LDAP server signing requirements are not enforced
    except Exception as e:
        print("\n   [!] "+ dcTarget+" -", str(e))
        return False

async def amain(method, dc_ip, fqdn, domainUser, password, timeout = 10):
    try:
        dcList = ResolveDCs(dc_ip, fqdn)
    except Exception as e:
        print("Error resolving DCs: " + str(e))
        exit()
    print("\n~Domain Controllers identified~")
    for dc in dcList:
        print("   " + dc)

    print("\n~Checking DCs for LDAP NTLM relay protections~")
    
    #print("VALUES AUTHING WITH:\nUser: "+domainUser+"\nPass: " +password + "\nDomain:  "+fqdn)

    cred = UniCredential(password, username=domainUser, domain=fqdn, stype=asyauthSecret.PASSWORD, protocol=asyauthProtocol.NTLM)

    for dc in dcList:
        print("   " + dc)
        try:
            if method == "BOTH":
                ldapIsProtected = await run_ldap(copy.deepcopy(cred), dc, timeout = timeout)
                if ldapIsProtected == False:
                    print("      [+] (LDAP)  SERVER SIGNING REQUIREMENTS NOT ENFORCED! ")
                elif ldapIsProtected == True:
                    print("      [-] (LDAP)  server enforcing signing requirements")
            if DoesLdapsCompleteHandshake(dc) == True:
                ldapsChannelBindingAlwaysCheck = await run_ldaps_noEPA(copy.deepcopy(cred), dc, timeout=timeout)
                ldapsChannelBindingWhenSupportedCheck = await run_ldaps_withEPA(copy.deepcopy(cred), dc, timeout=timeout)
                if ldapsChannelBindingAlwaysCheck == False and ldapsChannelBindingWhenSupportedCheck == True:
                    print("      [-] (LDAPS) channel binding is set to \"when supported\" - this")
                    print("                  may prevent an NTLM relay depending on the client's")
                    print("                  support for channel binding.")
                elif ldapsChannelBindingAlwaysCheck == False and ldapsChannelBindingWhenSupportedCheck == False:
                        print("      [+] (LDAPS) CHANNEL BINDING SET TO \"NEVER\"! PARTY TIME!")
                elif ldapsChannelBindingAlwaysCheck == True:
                    print("      [-] (LDAPS) channel binding set to \"required\", no fun allowed")
                else:
                    print("\nSomething went wrong...")
                    print("For troubleshooting:\nldapsChannelBindingAlwaysCheck - " +str(ldapsChannelBindingAlwaysCheck)+"\nldapsChannelBindingWhenSupportedCheck: "+str(ldapsChannelBindingWhenSupportedCheck))
                    exit()
                #print("For troubleshooting:\nldapsChannelBindingAlwaysCheck - " +str(ldapsChannelBindingAlwaysCheck)+"\nldapsChannelBindingWhenSupportedCheck: "+str(ldapsChannelBindingWhenSupportedCheck))
                    
            elif DoesLdapsCompleteHandshake(dc) == False:
                print("      [!] "+dc+ " - cannot complete TLS handshake, cert likely not configured")
        except Exception as e:
            print("      [-] ERROR: " + str(e))
    print()


def main():
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
    parser.add_argument('-timeout', default=10, metavar='timeout',action='store', type=int,
                        help='The timeout for MSLDAP client connection.')
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
    fqdn = asyncio.run(InternalDomainFromAnonymousLdap(options.dc_ip))

    asyncio.run(amain(options.method, options.dc_ip, fqdn, domainUser, password))
    

if __name__ == '__main__':
    main()
