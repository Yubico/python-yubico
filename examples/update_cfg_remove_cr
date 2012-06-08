#!/usr/bin/env python
"""
Set up a YubiKey for standard OTP with CR, then remove it.
"""

import sys
import struct
import yubico

slot=2

try:
    YK = yubico.find_yubikey(debug=True)
    print "Version : %s " % YK.version()
    print "Status  : %s " % YK.status()

    Cfg = YK.init_config()
    Cfg.extended_flag('ALLOW_UPDATE', True)
    Cfg.ticket_flag('APPEND_CR', True)
    Cfg.extended_flag('SERIAL_API_VISIBLE', True)
    Cfg.uid = '010203040506'.decode('hex')
    Cfg.fixed_string("m:ftccftbbftdd")
    Cfg.aes_key('h:' + 32 * 'a')

    user_input = raw_input('Write configuration to slot %i of YubiKey? [y/N] : ' % slot )
    if user_input in ('y', 'ye', 'yes'):
        YK.write_config(Cfg, slot=slot)
        print "\nSuccess!"
        print "Status  : %s " % YK.status()
    else:
        print "\nAborted"
        sys.exit(0)

    raw_input("Press enter to update...")

    Cfg = YK.init_config(update=True)
    Cfg.ticket_flag('APPEND_CR', False)

    print ("Updating...");
    YK.write_config(Cfg, slot=slot)
    print "\nSuccess!"
except yubico.yubico_exception.YubicoError as inst:
    print "ERROR: %s" % inst.reason
    sys.exit(1)
