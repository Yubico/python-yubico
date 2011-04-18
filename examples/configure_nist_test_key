#!/usr/bin/env python
"""
Set up a YubiKey with a NIST PUB 198 A.2
20 bytes test vector in Slot 2 (variable input)
"""

import sys
import struct
import yubico

slot=2

try:
    YK = yubico.find_yubikey(debug=True)
    print "Version : %s " % YK.version()

    Cfg = YK.init_config()
    key='h:303132333435363738393a3b3c3d3e3f40414243'
    Cfg.mode_challenge_response(key, type='HMAC', variable=True)
    Cfg.extended_flag('SERIAL_API_VISIBLE', True)

    user_input = raw_input('Write configuration to slot %i of YubiKey? [y/N] : ' % slot )
    if user_input in ('y', 'ye', 'yes'):
        YK.write_config(Cfg, slot=slot)
        print "\nSuccess!"
    else:
        print "\nAborted"
except yubico.yubico_exception.YubicoError as inst:
    print "ERROR: %s" % inst.reason
    sys.exit(1)
