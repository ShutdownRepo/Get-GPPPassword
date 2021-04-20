# Get-GPPPassword

Python script for extracting and decrypting Group Policy Preferences passwords.

## Usage

```
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

usage: Get-GPPPassword.py [-h] [-d DOMAIN]
                          [-u USERNAME]
                          [-p PASSWORD]
                          [-share SHARE] [-P PORT]
                          [-debug] [-ts]
                          server

Group Policy Preferences passwords finder and
decryptor

positional arguments:
  server                Target SMB server address

optional arguments:
  -h, --help            show this help message and
                        exit
  -d DOMAIN, --domain DOMAIN
                        SMB Password
  -u USERNAME, --username USERNAME
                        SMB Username
  -p PASSWORD, --password PASSWORD
                        SMB Password
  -share SHARE          SMB Share
  -P PORT, --port PORT  Server port
  -debug
  -ts                   Adds timestamp to every
```
