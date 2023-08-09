import requests
import argparse
import sys

if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=True, description="")
    parser.add_argument('inputfile', action='store', help='list of ips to check can be formatter IP or IP:PORT one per line')
    parser.add_argument('-i', action='store', help='Status codes to ignore list seperated by a comma eg 404,503,200')
    parser.add_argument('-o', action='store', help='output file')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    with open(options.inputfile, 'r') as f:
        dat = f.read()
        f.close()

    list1 = dat.split('\n')
    if options.i is not None:
        options.i = options.i.split(',')

    for item in list1:
        try:
            if len(item) > 1:
                x = requests.get('http://{}'.format(item), timeout=10)
                if options.i is not None:
                    if str(x.status_code) not in options.i:
                        print(item + " " + str(x.status_code))
                        if options.o is not None:
                            with open(options.o, 'a') as f:
                                f.write(item + " " + str(x.status_code) + '\n')
                                f.close()
                else:
                    print(item + " " + str(x.status_code))
                    if options.o is not None:
                        with open(options.o, 'a') as f:
                            f.write(item + " " + str(x.status_code) + '\n')
                            f.close()
        except BaseException as e:
            continue
