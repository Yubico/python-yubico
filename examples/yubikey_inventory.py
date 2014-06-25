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
        for skip in range(0, 256):
            y_key = yubico.find_yubikey(debug=debug, skip=skip)
            res.append(y_key)
    except yubico.yubikey.YubiKeyError:
        pass
    return res

def main(args):
    debug = False
    if len(args) > 1:
        debug = (args[1] == '-v')
    keys = get_all_yubikeys(debug)

    if not keys:
        print "No YubiKey found."
        return
    for i, this_key in enumerate(keys):
        print "YubiKey #%02i : %s %s" % (i + 1, this_key.description, this_key.status())

if __name__ == '__main__':
    main(sys.argv)
