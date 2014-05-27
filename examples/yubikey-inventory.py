#!/usr/bin/env python
"""
Example of how to access more than one connected YubiKey.
"""

import sys
import yubico

def get_all_yubikeys(debug):
    """
    Look for YubiKey with ever increasing `skip' value until an error is returned.

    Return all instances of class YubiKey we got before failing.
    """
    res = []
    try:
        skip = 0
        while skip < 255:
            YK = yubico.find_yubikey(debug = debug, skip = skip)
            res.append(YK)
            skip += 1
    except yubico.yubikey.YubiKeyError:
        pass
    return res

debug = False
if len(sys.argv) > 1:
    debug = (sys.argv[1] == '-v')
keys = get_all_yubikeys(debug)

if not keys:
    print "No YubiKey found."
else:
    n = 1
    for this in keys:
        print "YubiKey #%02i : %s %s" % (n, this.description, this.status())
        n += 1
