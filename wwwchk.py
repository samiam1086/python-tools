from urllib3.exceptions import InsecureRequestWarning
from requests import ConnectionError
import requests
import argparse
import sys


def get_title(response_text):
    if response_text.find('<title') == -1:
        return ''

    tmp = response_text[response_text.find('<title'):]
    tmp1 = ' Title: ' + tmp[tmp.find('>') + 1:tmp.find('</title>')]
    return tmp1


def https_chk(target):
    try:
        x = requests.get('https://{}'.format(target), timeout=5, verify=False)  # make an https request
        if options.i is not None:
            if str(x.status_code) not in options.i:
                print(x.url + " Status Code: " + str(x.status_code) + get_title(x.text))
                if options.o is not None:
                    with open(options.o, 'a') as f:
                        f.write(x.url + " Status Code: " + str(x.status_code) + get_title(x.text) + '\n')
                        f.close()
        else:
            print(x.url + " Status Code: " + str(x.status_code) + get_title(x.text))
            if options.o is not None:
                with open(options.o, 'a') as f:
                    f.write(x.url + " Status Code: " + str(x.status_code) + get_title(x.text) + '\n')
                    f.close()

    except KeyboardInterrupt:
        sys.exit(1)
    except BaseException as e:
        if options.se:
            if str(e).find('Max retries exceeded with url') != -1:
                print('Host {} is not alive'.format(target))
            else:
                print('Host {} returned an error {}'.format(target, e))
        if options.debug:
            import traceback

            traceback.print_exc()
        pass


if __name__ == '__main__':

    parser = argparse.ArgumentParser(add_help=True, description="")
    parser.add_argument('inputfile', action='store', help='list of ips to check can be formatted as IP or IP:PORT one per line')
    parser.add_argument('-i', action='store', help='Status codes to ignore list seperated by a comma eg 404,503,200')
    parser.add_argument('-o', action='store', help='output file')
    parser.add_argument('-debug', action='store_true', help='Turn on debugging')
    parser.add_argument('-se', action='store_false', help='Skip any errors from printing')

    # Suppress only the single warning from urllib3 needed.
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    with open(options.inputfile, 'r') as f:  # read our inputfile
        dat = f.read()
        f.close()

    target_list = dat.split('\n')  # split it into a list

    if options.i is not None:  # if they gave us an options.i lets make it a list the split function does not cause issues if there is no comma it will just appear as 1 string in the list
        options.i = options.i.split(',')

    for target in target_list:
        try:
            if len(target) > 0:
                x = requests.get('http://{}'.format(target), timeout=5)  # make an http request

                if x.status_code == 400:
                    https_chk(target)

                if options.i is not None:
                    if str(x.status_code) not in options.i:  # check if our response is a code designated to be ignroed
                        print(x.url + " Status Code: " + str(x.status_code) + get_title(x.text))  # print our output
                        if options.o is not None:
                            with open(options.o, 'a') as f:  # if options.o then save the target
                                f.write(x.url + " Status Code: " + str(x.status_code) + get_title(x.text) + '\n')
                                f.close()
                else:
                    print(x.url + " Status Code: " + str(x.status_code) + get_title(x.text))
                    if options.o is not None:
                        with open(options.o, 'a') as f:
                            f.write(x.url + " Status Code: " + str(x.status_code) + get_title(x.text) + '\n')
                            f.close()
        except KeyboardInterrupt:
            sys.exit(1)
        except requests.exceptions.ConnectionError:  # if the server is running https we should get this
            https_chk(target)
        except ConnectionResetError:
            https_chk(target)
        except BaseException as e:
            if options.se:
                if str(e).find('Max retries exceeded with url') != -1:
                    print('Host {} is not alive'.format(target))
                else:
                    print('Host {} returned an error {}'.format(target, e))
            if options.debug:
                import traceback

                traceback.print_exc()
            continue
