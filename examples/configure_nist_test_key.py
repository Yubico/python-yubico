#!/usr/bin/env python
"""
Set up a YubiKey with a NIST PUB 198 A.2
20 bytes test vector in Slot 2 (variable input)
"""

import sys
import yubico


def main():
    slot = 2

    try:
        y_key = yubico.find_yubikey(debug=True)
        print "Version : %s " % y_key.version()

        cfg = y_key.init_config()
        key = 'h:303132333435363738393a3b3c3d3e3f40414243'
        cfg.mode_challenge_response(key, type='HMAC', variable=True)
        cfg.extended_flag('SERIAL_API_VISIBLE', True)

        user_input = raw_input('Write configuration to slot %i of YubiKey? [y/N] : ' % slot)
        if user_input.lower() in ('y', 'ye', 'yes'):
            y_key.write_config(cfg, slot=slot)
            print "\nSuccess!"
        else:
            print "\nAborted"
    except yubico.yubico_exception.YubicoError as inst:
        print "ERROR: %s" % inst.reason
        return 2

if __name__ == '__main__':
    sys.exit(main())
