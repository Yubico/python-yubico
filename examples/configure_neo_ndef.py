#!/usr/bin/env python
"""
Set up a YubiKey NEO NDEF
"""

import sys

import yubico
import yubico.yubikey_neo_usb_hid

def main(args):
    if len(args) != 2:
        sys.stderr.write("Syntax: %s URL\n" % args)
        return 1

    url = args[1]

    try:
        y_key = yubico.yubikey_neo_usb_hid.YubiKeyNEO_USBHID(debug=True)
        print "Version : %s " % y_key.version()

        ndef = yubico.yubikey_neo_usb_hid.YubiKeyNEO_NDEF(data=url)

        user_input = raw_input('Write configuration to YubiKey? [y/N] : ')
        if user_input.lower() in ('y', 'ye', 'yes'):
            y_key.write_ndef(ndef)
            print "\nSuccess!"
        else:
            print "\nAborted"
    except yubico.yubico_exception.YubicoError as inst:
        print "ERROR: %s" % inst.reason
        return 2

if __name__ == '__main__':
    sys.exit(main(sys.argv))
