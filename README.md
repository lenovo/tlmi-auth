# tlmi-auth

Utility for creating signature strings needed for thinklmi certificate based authentication

## Building

### Prerequisites

- Meson 0.54 or newer
- A C compiler (tested with GCC >= 8.0)
- OpenSSL 1.1 or newer

#### Fedora Linux / Red Hat Enterprise Linux / CentOS Stream

`sudo dnf install meson gcc openssl-devel`

#### Debian / Ubuntu

`sudo apt install meson gcc libssl-dev`

### Build and install steps

1. `meson setup . build`
2. `meson compile -C build`
3. `meson install -C build`

`tlmi-auth` will be installed into `/usr/local/bin` by default.

## Usage

```
Usage: tlmi-auth command [option]

Where commands are

  setcert -c cert.pem -p passwd                  - Set installed certificate

  updatecert -c cert.pem -k privkey.pem          - Update installed certificate

  clearcert -s serial -k privkey.pem             - Clear installed certificate

  attribute -a attribute -v value -k privkey.pem - Set attribute to given value

  cert2pass -p passwd -k privkey.pem             - Go from certificate to password authentication

  unlock -f request.txt -k privkey.pem           - Generate unlock code from request file.

  unlock -r request-string -k privkey.pem        - Generate unlock code from request string.

* -d option can be used instead of -c for DER formatted certificates.

* -o option specifies output filename.

* -u option can be used to specify password for the private key.

* -q option will inhibit all informative messages

* -h displays this message

The tool will create a thinklmi.sh file (unless name specified by the -o option). This file has the commands that need to be run on the client system.
```

## Implementation

Please note that this source code serves as an example implementation only.

Users should take care to store any keys and certificates in appropriate secure storage.

## Legal
This code is distributed under GPL-v2 license with full text of the license 
located in the COPYING file.

[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](code_of_conduct.md)

