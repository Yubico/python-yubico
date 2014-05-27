#!/usr/bin/env python
"""
Test challenge-response, assumes a NIST PUB 198 A.2
20 bytes test vector in Slot 2 (variable input)
"""

import sys
import yubico

def main(args):

    expected = \
      '\x09\x22\xd3\x40\x5f\xaa\x3d\x19\x4f\x82' + \
      '\xa4\x58\x30\x73\x7d\x5c\xc6\xc7\x5d\x24'

    # turn on YubiKey debug if -v is given as an argument
    debug = False
    if len(args) > 1:
        debug = (args == '-v')

    # Look for and initialize the YubiKey
    try:
        y_key = yubico.find_yubikey(debug=debug)
        print "Version : %s " % y_key.version()
        print "Serial  : %i" % y_key.serial()
        print ""

        # Do challenge-response
        secret = 'Sample #2'.ljust(64, chr(0x0))
        print "Sending challenge : %s\n" % repr(secret)

        response = y_key.challenge_response(secret, slot=2)
    except yubico.yubico_exception.YubicoError as inst:
        print "ERROR: %s" % inst.reason
        return 2

    print "Response :\n%s\n" % yubico.yubico_util.hexdump(response)

    # Check if the response matched the expected one
    if response == expected:
        print "OK! Response matches the NIST PUB 198 A.2 expected response."
        return 0
    else:
        print "ERROR! Response does NOT match the NIST PUB 198 A.2 expected response."
        return 2

if __name__ == '__main__':
    sys.exit(main(sys.argv))
