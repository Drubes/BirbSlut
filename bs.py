#!/usr/bin/python
# -*- coding: utf-8 -*-
import requests
import base64
import sys
import argparse
from dbase import *
from funcy import *
import logging
import time

#parsh the arguments.###########################################################

desc = "BawlSec\'s BirbSlut: \n\n"\
       "A cheap & crappy replacement for Burpsuits intruder.\n"\
       "for now it only attacks using the batterram methode.\n"\
       "and uses only lists as payloads... \n"\
       "but hey, it's faster than the community edition\n\n"\
       "anyway: it replaces the magic word BECKY with the payloads\n"\
       "from the profided list it stores the resulst in a sqlite db.\n"


parser = argparse.ArgumentParser(description=desc)
parser.add_argument('dbname',
                    metavar='<db path>',
                    type=str,
                    help='path / name of database')

parser.add_argument('url',
                    metavar='<url>',
                    type=str,
                    help='the target URL')

parser.add_argument('payloads',
                    metavar='<pl path>',
                    type=str,
                    help='path to the payload list')

parser.add_argument('-d',
                    dest='post_data',
                    type=str,
                    action='append',
                    help='post data   -d data=hey -d page=becky')

parser.add_argument('-g',
                    dest='get_data',
                    type=str,
                    action='append',
                    help='post data   -g q=lemme -g page=smash')


parser.add_argument('-H',
                    dest='headers',
                    type=str,
                    help='headers  -H user-agent=MozillaMoproblems -H X-forwared-for=127.0.0.1',
                    action='append')

parser.add_argument('-M',
                    dest='methode',
                    type=str,
                    choices = ["GET", "HEAD", "POST", "PUT", "DELETE","CONNECT", "OPTIONS", "TRACE"],
                    default = "GET",
                    help='Request methode.')
                    #choices = ["GET", "POST"],

parser.add_argument('-m',
                    dest='timeout',
                    type=str,
                    default = 30,
                    help='max time per request in seconds.')

parser.add_argument('--b64',
                    dest='base',
                    action='store_true',
                    help='Payloads in file are base64 encoded.')

parser.add_argument('-v',
                    dest='verbose',
                    choices = [0, 1, 2, 3, 4, 5],
                    type=int,
                    default=1,
                    help='verbosety, 5=CRITICAL 4=ERROR 3=WARNING 2=INFO 1=DEBUG 0=NOTSET')


parser.add_argument('-t',
                    dest='treads',
                    type=int,
                    default=10,
                    help='amount of treads (not implemented yet)')

args = parser.parse_args()

target      = args.url
payloadfile = args.payloads
timeout     = args.timeout
methode     = args.methode
headers     = args.headers
treads      = args.treads
dbname      = args.dbname
post_data   = args.post_data
get_data    = args.get_data
is_base64   = args.base

logging.basicConfig(level=args.verbose*10)
log = logging.getLogger(__name__)

#log.logger.setLevel()

################################################################################
def drop_payload(payload):
    injected_data=inject_payload(data_dic, payload)
    injected_headers=inject_payload(header_dic, payload)
    injected_params=inject_payload(param_dic, payload)
    timestamp = int(time.time())
    if methode == "GET":
        r = requests.get(target, headers=injected_headers, params=injected_params, data=injected_data, timeout=timeout)
    if methode == "HEAD":
        r = requests.head(target, headers=injected_headers, params=injected_params, data=injected_data, timeout=timeout)
    if methode == "POST":
        r = requests.post(target, headers=injected_headers, params=injected_params, data=injected_data, timeout=timeout)
    if methode == "PUT":
        r = requests.put(target, headers=injected_headers, params=injected_params, data=injected_data, timeout=timeout)
    if methode == "DELETE":
        r = requests.delete(target, headers=injected_headers, params=injected_params, data=injected_data, timeout=timeout)
    if methode == "CONNECT":
        r = requests.connect(target, headers=injected_headers, params=injected_params, data=injected_data, timeout=timeout)
    if methode == "OPTIONS":
        r = requests.options(target, headers=injected_headers, params=injected_params, data=injected_data, timeout=timeout)
    if methode == "TRACE":
        r = requests.trace(target, headers=injected_headers, params=injected_params, data=injected_data, timeout=timeout)
    timedif = timestamp-int(time.time())
    url = r.url
    status = int(r.status_code)
    log.debug(status)
    size = int(r.headers['Content-Length'])
    headers = str(r.headers)
    content = r.text
    d.add_req(url,timestamp,timedif,str(injected_headers),str(injected_data),status,headers,content,size)


################################################################################
# handle payloads list.
payloads = get_payloads(payloadfile)
if is_base64:
    payloads = decode_payloads(payloads)

################################################################################
# connect to database.
d = bsdb(dbname)

################################################################################
# prepair headers.
if headers != None:
    header_dic = data_to_dic(headers)
else:
    header_dic = {"user-agent":"HeybeckyLetme-smash."}

################################################################################
#  prepare postdata.
if post_data:
    data_dic = data_to_dic(post_data)
else:
    data_dic = {}

################################################################################
#  prepare postdata.
if get_data:
    param_dic = data_to_dic(get_data)
else:
    param_dic = {}


################################################################################
#
log.info("dropping "+str(len(payloads))+" payloads")
for payload in payloads:
    #print payload[:-1]
    log.debug(payload[:-1])  #fucking tailing \n
    drop_payload(payload[:-1])




'''
CURL HELP AS REFERRENCE..
Usage: curl [options...] <url>
     --abstract-unix-socket <path> Connect via abstract Unix domain socket
     --anyauth       Pick any authentication method
 -a, --append        Append to target file when uploading
     --basic         Use HTTP Basic Authentication
     --cacert <file> CA certificate to verify peer against
     --capath <dir>  CA directory to verify peer against
 -E, --cert <certificate[:password]> Client certificate file and password
     --cert-status   Verify the status of the server certificate
     --cert-type <type> Certificate file type (DER/PEM/ENG)
     --ciphers <list of ciphers> SSL ciphers to use
     --compressed    Request compressed response
     --compressed-ssh Enable SSH compression
 -K, --config <file> Read config from a file
     --connect-timeout <seconds> Maximum time allowed for connection
     --connect-to <HOST1:PORT1:HOST2:PORT2> Connect to host
 -C, --continue-at <offset> Resumed transfer offset
 -b, --cookie <data> Send cookies from string/file
 -c, --cookie-jar <filename> Write cookies to <filename> after operation
     --create-dirs   Create necessary local directory hierarchy
     --crlf          Convert LF to CRLF in upload
     --crlfile <file> Get a CRL list in PEM format from the given file
 -d, --data <data>   HTTP POST data
     --data-ascii <data> HTTP POST ASCII data
     --data-binary <data> HTTP POST binary data
     --data-raw <data> HTTP POST data, '@' allowed
     --data-urlencode <data> HTTP POST data url encoded
     --delegation <LEVEL> GSS-API delegation permission
     --digest        Use HTTP Digest Authentication
 -q, --disable       Disable .curlrc
     --disable-eprt  Inhibit using EPRT or LPRT
     --disable-epsv  Inhibit using EPSV
     --disallow-username-in-url Disallow username in url
     --dns-interface <interface> Interface to use for DNS requests
     --dns-ipv4-addr <address> IPv4 address to use for DNS requests
     --dns-ipv6-addr <address> IPv6 address to use for DNS requests
     --dns-servers <addresses> DNS server addrs to use
     --doh-url <URL> Resolve host names over DOH
 -D, --dump-header <filename> Write the received headers to <filename>
     --egd-file <file> EGD socket path for random data
     --engine <name> Crypto engine to use
     --expect100-timeout <seconds> How long to wait for 100-continue
 -f, --fail          Fail silently (no output at all) on HTTP errors
     --fail-early    Fail on first transfer error, do not continue
     --false-start   Enable TLS False Start
 -F, --form <name=content> Specify multipart MIME data
     --form-string <name=string> Specify multipart MIME data
     --ftp-account <data> Account data string
     --ftp-alternative-to-user <command> String to replace USER [name]
     --ftp-create-dirs Create the remote dirs if not present
     --ftp-method <method> Control CWD usage
     --ftp-pasv      Use PASV/EPSV instead of PORT
 -P, --ftp-port <address> Use PORT instead of PASV
     --ftp-pret      Send PRET before PASV
     --ftp-skip-pasv-ip Skip the IP address for PASV
     --ftp-ssl-ccc   Send CCC after authenticating
     --ftp-ssl-ccc-mode <active/passive> Set CCC mode
     --ftp-ssl-control Require SSL/TLS for FTP login, clear for transfer
 -G, --get           Put the post data in the URL and use GET
 -g, --globoff       Disable URL sequences and ranges using {} and []
     --happy-eyeballs-timeout-ms <milliseconds> How long to wait in milliseconds for IPv6 before trying IPv4
     --haproxy-protocol Send HAProxy PROXY protocol v1 header
 -I, --head          Show document info only
 -H, --header <header/@file> Pass custom header(s) to server
 -h, --help          This help text
     --hostpubmd5 <md5> Acceptable MD5 hash of the host public key
     --http0.9       Allow HTTP 0.9 responses
 -0, --http1.0       Use HTTP 1.0
     --http1.1       Use HTTP 1.1
     --http2         Use HTTP 2
     --http2-prior-knowledge Use HTTP 2 without HTTP/1.1 Upgrade
     --ignore-content-length Ignore the size of the remote resource
 -i, --include       Include protocol response headers in the output
 -k, --insecure      Allow insecure server connections when using SSL
     --interface <name> Use network INTERFACE (or address)
 -4, --ipv4          Resolve names to IPv4 addresses
 -6, --ipv6          Resolve names to IPv6 addresses
 -j, --junk-session-cookies Ignore session cookies read from file
     --keepalive-time <seconds> Interval time for keepalive probes
     --key <key>     Private key file name
     --key-type <type> Private key file type (DER/PEM/ENG)
     --krb <level>   Enable Kerberos with security <level>
     --libcurl <file> Dump libcurl equivalent code of this command line
     --limit-rate <speed> Limit transfer speed to RATE
 -l, --list-only     List only mode
     --local-port <num/range> Force use of RANGE for local port numbers
 -L, --location      Follow redirects
     --location-trusted Like --location, and send auth to other hosts
     --login-options <options> Server login options
     --mail-auth <address> Originator address of the original email
     --mail-from <address> Mail from this address
     --mail-rcpt <address> Mail to this address
 -M, --manual        Display the full manual
     --max-filesize <bytes> Maximum file size to download
     --max-redirs <num> Maximum number of redirects allowed
 -m, --max-time <seconds> Maximum time allowed for the transfer
     --metalink      Process given URLs as metalink XML file
     --negotiate     Use HTTP Negotiate (SPNEGO) authentication
 -n, --netrc         Must read .netrc for user name and password
     --netrc-file <filename> Specify FILE for netrc
     --netrc-optional Use either .netrc or URL
 -:, --next          Make next URL use its separate set of options
     --no-alpn       Disable the ALPN TLS extension
 -N, --no-buffer     Disable buffering of the output stream
     --no-keepalive  Disable TCP keepalive on the connection
     --no-npn        Disable the NPN TLS extension
     --no-sessionid  Disable SSL session-ID reusing
     --noproxy <no-proxy-list> List of hosts which do not use proxy
     --ntlm          Use HTTP NTLM authentication
     --ntlm-wb       Use HTTP NTLM authentication with winbind
     --oauth2-bearer <token> OAuth 2 Bearer Token
 -o, --output <file> Write to file instead of stdout
     --pass <phrase> Pass phrase for the private key
     --path-as-is    Do not squash .. sequences in URL path
     --pinnedpubkey <hashes> FILE/HASHES Public key to verify peer against
     --post301       Do not switch to GET after following a 301
     --post302       Do not switch to GET after following a 302
     --post303       Do not switch to GET after following a 303
     --preproxy [protocol://]host[:port] Use this proxy first
 -#, --progress-bar  Display transfer progress as a bar
     --proto <protocols> Enable/disable PROTOCOLS
     --proto-default <protocol> Use PROTOCOL for any URL missing a scheme
     --proto-redir <protocols> Enable/disable PROTOCOLS on redirect
 -x, --proxy [protocol://]host[:port] Use this proxy
     --proxy-anyauth Pick any proxy authentication method
     --proxy-basic   Use Basic authentication on the proxy
     --proxy-cacert <file> CA certificate to verify peer against for proxy
     --proxy-capath <dir> CA directory to verify peer against for proxy
     --proxy-cert <cert[:passwd]> Set client certificate for proxy
     --proxy-cert-type <type> Client certificate type for HTTPS proxy
     --proxy-ciphers <list> SSL ciphers to use for proxy
     --proxy-crlfile <file> Set a CRL list for proxy
     --proxy-digest  Use Digest authentication on the proxy
     --proxy-header <header/@file> Pass custom header(s) to proxy
     --proxy-insecure Do HTTPS proxy connections without verifying the proxy
     --proxy-key <key> Private key for HTTPS proxy
     --proxy-key-type <type> Private key file type for proxy
     --proxy-negotiate Use HTTP Negotiate (SPNEGO) authentication on the proxy
     --proxy-ntlm    Use NTLM authentication on the proxy
     --proxy-pass <phrase> Pass phrase for the private key for HTTPS proxy
     --proxy-pinnedpubkey <hashes> FILE/HASHES public key to verify proxy with
     --proxy-service-name <name> SPNEGO proxy service name
     --proxy-ssl-allow-beast Allow security flaw for interop for HTTPS proxy
     --proxy-tls13-ciphers <ciphersuite list> TLS 1.3 proxy cipher suites
     --proxy-tlsauthtype <type> TLS authentication type for HTTPS proxy
     --proxy-tlspassword <string> TLS password for HTTPS proxy
     --proxy-tlsuser <name> TLS username for HTTPS proxy
     --proxy-tlsv1   Use TLSv1 for HTTPS proxy
 -U, --proxy-user <user:password> Proxy user and password
     --proxy1.0 <host[:port]> Use HTTP/1.0 proxy on given port
 -p, --proxytunnel   Operate through an HTTP proxy tunnel (using CONNECT)
     --pubkey <key>  SSH Public key file name
 -Q, --quote         Send command(s) to server before transfer
     --random-file <file> File for reading random data from
 -r, --range <range> Retrieve only the bytes within RANGE
     --raw           Do HTTP "raw"; no transfer decoding
 -e, --referer <URL> Referrer URL
 -J, --remote-header-name Use the header-provided filename
 -O, --remote-name   Write output to a file named as the remote file
     --remote-name-all Use the remote file name for all URLs
 -R, --remote-time   Set the remote file's time on the local output
 -X, --request <command> Specify request command to use
     --request-target Specify the target for this request
     --resolve <host:port:address[,address]...> Resolve the host+port to this address
     --retry <num>   Retry request if transient problems occur
     --retry-connrefused Retry on connection refused (use with --retry)
     --retry-delay <seconds> Wait time between retries
     --retry-max-time <seconds> Retry only within this period
     --sasl-ir       Enable initial response in SASL authentication
     --service-name <name> SPNEGO service name
 -S, --show-error    Show error even when -s is used
 -s, --silent        Silent mode
     --socks4 <host[:port]> SOCKS4 proxy on given host + port
     --socks4a <host[:port]> SOCKS4a proxy on given host + port
     --socks5 <host[:port]> SOCKS5 proxy on given host + port
     --socks5-basic  Enable username/password auth for SOCKS5 proxies
     --socks5-gssapi Enable GSS-API auth for SOCKS5 proxies
     --socks5-gssapi-nec Compatibility with NEC SOCKS5 server
     --socks5-gssapi-service <name> SOCKS5 proxy service name for GSS-API
     --socks5-hostname <host[:port]> SOCKS5 proxy, pass host name to proxy
 -Y, --speed-limit <speed> Stop transfers slower than this
 -y, --speed-time <seconds> Trigger 'speed-limit' abort after this time
     --ssl           Try SSL/TLS
     --ssl-allow-beast Allow security flaw to improve interop
     --ssl-no-revoke Disable cert revocation checks (Schannel)
     --ssl-reqd      Require SSL/TLS
 -2, --sslv2         Use SSLv2
 -3, --sslv3         Use SSLv3
     --stderr        Where to redirect stderr
     --styled-output Enable styled output for HTTP headers
     --suppress-connect-headers Suppress proxy CONNECT response headers
     --tcp-fastopen  Use TCP Fast Open
     --tcp-nodelay   Use the TCP_NODELAY option
 -t, --telnet-option <opt=val> Set telnet option
     --tftp-blksize <value> Set TFTP BLKSIZE option
     --tftp-no-options Do not send any TFTP options
 -z, --time-cond <time> Transfer based on a time condition
     --tls-max <VERSION> Set maximum allowed TLS version
     --tls13-ciphers <list of TLS 1.3 ciphersuites> TLS 1.3 cipher suites to use
     --tlsauthtype <type> TLS authentication type
     --tlspassword   TLS password
     --tlsuser <name> TLS user name
 -1, --tlsv1         Use TLSv1.0 or greater
     --tlsv1.0       Use TLSv1.0 or greater
     --tlsv1.1       Use TLSv1.1 or greater
     --tlsv1.2       Use TLSv1.2 or greater
     --tlsv1.3       Use TLSv1.3 or greater
     --tr-encoding   Request compressed transfer encoding
     --trace <file>  Write a debug trace to FILE
     --trace-ascii <file> Like --trace, but without hex output
     --trace-time    Add time stamps to trace/verbose output
     --unix-socket <path> Connect through this Unix domain socket
 -T, --upload-file <file> Transfer local FILE to destination
     --url <url>     URL to work with
 -B, --use-ascii     Use ASCII/text transfer
 -u, --user <user:password> Server user and password
 -A, --user-agent <name> Send User-Agent <name> to server
 -v, --verbose       Make the operation more talkative
 -V, --version       Show version number and quit
 -w, --write-out <format> Use output FORMAT after completion
     --xattr         Store metadata in extended file attributes
'''
