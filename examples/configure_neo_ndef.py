#!/usr/bin/env python
"""
Set up a YubiKey NEO NDEF
"""

import sys
import struct
import urllib

import yubico
import yubico.yubikey_neo_usb_hid

if len(sys.argv) != 2:
    sys.stderr.write("Syntax: %s URL\n" % (sys.argv[0]))
    sys.exit(1)

url = sys.argv[1]

try:
    YK = yubico.yubikey_neo_usb_hid.YubiKeyNEO_USBHID(debug=True)
    print "Version : %s " % YK.version()

    ndef = yubico.yubikey_neo_usb_hid.YubiKeyNEO_NDEF(data = url)

    user_input = raw_input('Write configuration to YubiKey? [y/N] : ')
    if user_input in ('y', 'ye', 'yes'):
        YK.write_ndef(ndef)
        print "\nSuccess!"
    else:
        print "\nAborted"
except yubico.yubico_exception.YubicoError as inst:
    print "ERROR: %s" % inst.reason
    sys.exit(1)
