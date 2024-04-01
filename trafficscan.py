import concurrent.futures
import netifaces as ni
import socket, errno
import dns.message
import ipaddress
import dns.query
import binascii
import argparse
import random
import sys
import os

# colors
color_RED = '\033[91m'
color_GRE = '\033[92m'
color_YELL = '\033[93m'
color_reset = '\033[0m'

def llmnr_log(ip, hostname):
    with open('llmnr.hosts', 'a') as f:
        f.write('{} {}\n'.format(ip, hostname))
        f.close()

def mdns_log(ip):
    with open('mdns.hosts', 'a') as f:
        f.write('{}\n'.format(ip))
        f.close()

def netbios_log(ip, hostname):
    with open('netbios.hosts', 'a') as f:
        f.write('{} {}\n'.format(ip, hostname))
        f.close()


def is_port_in_use(port, local_ip): # function to check if a port is in use
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.bind((local_ip, port))
    except socket.error as e:
        if e.errno == errno.EADDRINUSE:
            return True
        else:
            # something else raised the socket.error exception
            print(e)
            return True

    s.close()
    return False


def send_mdns_query(host, local_ip, debug):
    try:
        question = '_services._dns-sd._udp.local' # this is now you make an mdns query i think

        src_port = random.randrange(15000, 50000) # get a random port
        ipiu = is_port_in_use(src_port, local_ip)
        while ipiu: # ensure the port is not in use
            src_port = random.randrange(15000, 50000)
            ipiu = is_port_in_use(src_port)

        if debug: # debug prints
            print('Sending MDNS Query for: {}:5353 from {}:{}'.format(host, local_ip, src_port))

        query = dns.message.make_query(question, rdtype=dns.rdatatype.PTR, rdclass=dns.rdataclass.IN) # make our dns query
        response = dns.query.udp(query, '224.0.0.251', port=5353, timeout=5, source=local_ip, source_port=src_port) # send the query

        if response.answer: # if the query came back then there is mdns in the environment
            mdns_log(host) # log the host
            if debug: # if we are debugging give the actual mdns response
                return 'MDNS Response: {}\n'.format(response.answer[0].to_text())
            else: # otherwise just return yes
                return 'MDNS:'.ljust(10) + '{}YES{}\n'.format(color_RED, color_reset)
        else: # if we did not get a response then mdns is closed
            return 'MDNS:'.ljust(10) + '{}NO{}\n'.format(color_GRE, color_reset)
    except Exception as e: # an exception occurred
        if debug: # if were debugging give verbose error
            return 'MDNS Response: {}\n'.format(str(e))
        else: # otherwise it is likely that mdns is closed
            return 'MDNS:'.ljust(10) + '{}NO{}\n'.format(color_GRE, color_reset)


def send_llmnr_query(host, local_ip, debug):
    try:
        # Build the PTR query
        question = 'in-addr.arpa'
        split_address = host.split('.')
        split_address.reverse()
        question = '.'.join(split_address) + '.' + question # this changes the ip to a reversed form so 10.1.20.3 goes to 3.20.1.10.in-addr.arpa

        src_port = random.randrange(15000,50000) # get a random port for src
        ipiu = is_port_in_use(src_port, local_ip)
        while ipiu: # ensure the port is not in use
            src_port = random.randrange(15000, 50000)
            ipiu = is_port_in_use(src_port)

        if debug: # verbose debugging
            print('Sending LLMNR Query for: {}:5355 from {}:{}'.format(host, local_ip, src_port))

        query = dns.message.make_query(question, rdtype=dns.rdatatype.PTR, rdclass=dns.rdataclass.IN) # make our dns query
        response = dns.query.udp(query, '224.0.0.252', port=5355, timeout=5, source=local_ip, source_port=src_port) # send the dns query to the victim

        if response.answer: # if we got a response llmnr is present on the host
            try:
                if response.answer[0].to_text().split(' ')[4].endswith('.'):
                    llmnr_log(host, response.answer[0].to_text().split(' ')[4].replace('.', '')) # log the host ip
                else:
                    llmnr_log(host, response.answer[0].to_text().split(' ')[4])
            except IndexError:
                llmnr_log(host, '')
            if debug: # if we are debugging give the actual llmnr response
                return 'LLMNR Response: {}\n'.format(response.answer[0].to_text())
            else: # if were not debugging just return yes
                return 'LLMNR:'.ljust(10) + '{}YES{}\n'.format(color_RED, color_reset)
        else: # if no response was given then llmnr is closed
            return 'LLMNR:'.ljust(10) + '{}NO{}\n'.format(color_GRE, color_reset)
    except Exception as e: # we got an error
        if debug: # if were debugging give the actual error
            return 'LLMNR Response: {}\n'.format(str(e))
        else: # otherwise just return no as llmnr is likely closed
            return 'LLMNR:'.ljust(10) + '{}NO{}\n'.format(color_GRE, color_reset)


def netbios_scan(host, debug): # scan for netbios using nbtscan
    # NetBIOS-NS packet structure: Transaction ID, Flags, Questions, Answer RRs, Authority RRs, Additional RRs, Name, Type, Class, TTL, Length, Number of names
    message = b'\x00\x00' + b'\x00\x10' + b'\x00\x01' + b'\x00\x00' + b'\x00\x00' + b'\x00\x00' + b'\x20' + b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' + b'\x00' + b'\x00\x21' + b'\x00\x01'
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    try:
        sock.sendto(message, (host, 137))
        data = sock.recvfrom(1024)
        data = data[0] # we are returned a list and the first item is the actual response
    except socket.timeout:
        sock.close()
        if debug:
            return f"Timeout during communication with {host}\n"
        else:
            return '{}NO{}\n'.format(color_GRE, color_reset)

    except Exception as e:
        sock.close()
        if debug:
            return f"Error during communication: {e}\n"
        else:
            return '{}NO{}\n'.format(color_GRE, color_reset)

    else:
        sock.close()

        # Parse response
        if len(data) < 57:  # Basic validation
            output = "Invalid response length\n"

        # The NetBIOS Name
        try:  # attempts to get the netbios name if we fail to decode just let em know
            netbiosname = data[57:57 + 15].decode('ascii').strip()
        except UnicodeDecodeError:
            try:
                netbiosname = data[57:57 + 15].decode('utf-8').strip()
            except UnicodeDecodeError:
                netbiosname = 'Failed to decode'
            except Exception:
                netbiosname = 'Unable to parse'
        except Exception:
            netbiosname = 'Unable to parse'

        # MAC address starts at byte 57+15+2=74, 6 bytes long
        try:
            macaddress = binascii.hexlify(data[74:80]).decode('ascii')
            macaddress_formatted = ':'.join(macaddress[i:i + 2] for i in range(0, len(macaddress), 2))
        except UnicodeDecodeError:
            try:
                macaddress = binascii.hexlify(data[74:80]).decode('ascii')
                macaddress_formatted = ':'.join(macaddress[i:i + 2] for i in range(0, len(macaddress), 2))
            except UnicodeDecodeError:
                macaddress_formatted = 'Failed to decode'
            except Exception:
                netbiosname = 'Unable to parse'
        except Exception:
            netbiosname = 'Unable to parse'

        if debug:
            output = f"NetBIOS Name: '{netbiosname}'" + f" MAC Address: '{macaddress_formatted}'\n"
        else:
            output = '{}YES{}\n'.format(color_RED, color_reset)

        netbios_log(host, netbiosname)
        return output


def mt_execute(host, local_ip, debug): # allows for multithreading

    out_data = '' # initialize our string
    out_data += 'Host: {}\n'.format(host) # print the host ip
    out_data += send_llmnr_query(host, local_ip, debug) # check llmnr
    out_data += 'NetBIOS:'.ljust(10) + '{}'.format(netbios_scan(host, debug)) # check netbios
    out_data += send_mdns_query(host, local_ip, debug) # check mdns
    return out_data


def parse_hosts_file(hosts_file): # parse our host file
    hosts = []
    try:
        with open(hosts_file, 'r') as file:
            for line in file:
                line = line.strip()
                if line:
                    if '/' in line:
                        # Assuming CIDR notation
                        network = ipaddress.ip_network(line, strict=False)
                        hosts.extend(str(ip) for ip in network.hosts())
                    else:
                        hosts.append(line)
        return hosts
    except FileNotFoundError:
        print('The given file does not exist')
        sys.exit(1)


def scan_hosts(hosts, output_file, local_ip, threads, debug): # scan our hosts with multithreading

    with open(output_file, "w") as log_file:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for host in hosts:
                if host != local_ip: # ensure we dont scan ourself
                    futures.append(executor.submit(mt_execute, host, local_ip, debug))
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                print(result)
                log_file.write(result + '\n')


def check_write_perms(): # checks if we can write to the location that our logs end up to ensure there are no errors
    try:
        with open('test_xzngfejwoeigj11jw', 'w') as f:
            f.write('1')
            f.close()
    except PermissionError:
        print('Permission Error you likely just need to run this as sudo')
        sys.exit(1)
    else:
        os.remove('test_xzngfejwoeigj11jw')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check if hosts are running LLMNR.") # argparse
    parser.add_argument("hosts_file", help="Path to a file containing hosts, either as individual IPs or in CIDR notation.")
    parser.add_argument('-ip', action='store', help='Your local ip or interface')
    parser.add_argument("-o", "--output_file", default="scan_log.txt", help="Output file name.")
    parser.add_argument('-t', '--threads', action='store', default=5, type=int, help='Number of threads to use (Default=5)')
    parser.add_argument('-debug', action='store_true', help='Enable debugging')
    args = parser.parse_args()

    hosts = parse_hosts_file(args.hosts_file) # get out hosts from the specified hosts_file

    check_write_perms()

    if args.ip is not None:  # did they give us the local ip in the command line
        local_ip = args.ip
        ifaces = ni.interfaces()
        iface_ips = []

        for face in ifaces: # get all interface ips
            try:
                iface_ips.append(ni.ifaddresses(face)[ni.AF_INET][0]['addr'])
            except BaseException as exc:
                continue

        try:  # check to see if the interface has an ip
            if local_ip in ifaces: # if the given ip is one of our interfaces
                local_ip = str(ni.ifaddresses(local_ip)[ni.AF_INET][0]['addr']) # get the ip address of the interface
                print("local IP => {}\n".format(local_ip))
            elif local_ip in iface_ips:
                print("local IP => {}\n".format(local_ip))
            else:
                print('The interface or IP you specified does not belong to the local machine')
                sys.exit(0)
        except SystemExit:
            sys.exit(0)
        except BaseException as exc:
            print('{}[!!]{} Error could not get that interface\'s address. Does it have an IP?'.format(color_RED, color_reset))
            sys.exit(0)
    else:
        # print local interfaces and ips
        print("")
        ifaces = ni.interfaces()
        iface_ips = []

        for face in ifaces: # get all interface ips
            try:
                iface_ips.append(ni.ifaddresses(face)[ni.AF_INET][0]['addr'])
            except BaseException as exc:
                continue

        for face in ifaces:
            try:  # check to see if the interface has an ip
                print('{} {}'.format(str(face + ':').ljust(20), ni.ifaddresses(face)[ni.AF_INET][0]['addr']))
            except BaseException as exc:
                continue

        local_ip = input("\nEnter you local ip or interface: ")

        # lets you enter eth0 as the ip
        try:  # check to see if the interface has an ip
            if local_ip in ifaces:
                local_ip = str(ni.ifaddresses(local_ip)[ni.AF_INET][0]['addr'])
                print("local IP => {}\n".format(local_ip))
            elif local_ip in iface_ips:
                print("local IP => {}\n".format(local_ip))
            else:
                print('The interface or IP you specified does not belong to the local machine')
                sys.exit(0)
        except SystemExit:
            sys.exit(0)
        except BaseException as exc:
            print('{}[!!]{} Error could not get that interface\'s address. Does it have an IP?'.format(color_RED, color_reset))
            sys.exit(0)

    scan_hosts(hosts, args.output_file, local_ip, args.threads, args.debug)
    
