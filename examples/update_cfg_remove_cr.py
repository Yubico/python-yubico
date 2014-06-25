#!/usr/bin/env python
"""
Set up a YubiKey for standard OTP with CR, then remove it.
"""

import sys
import yubico

def main():

    slot = 2

    try:
        y_key = yubico.find_yubikey(debug=True)
        print "Version : %s " % y_key.version()
        print "Status  : %s " % y_key.status()

        cfg = y_key.init_config()
        cfg.extended_flag('ALLOW_UPDATE', True)
        cfg.ticket_flag('APPEND_CR', True)
        cfg.extended_flag('SERIAL_API_VISIBLE', True)
        cfg.uid = '010203040506'.decode('hex')
        cfg.fixed_string("m:ftccftbbftdd")
        cfg.aes_key('h:' + 32 * 'a')

        user_input = raw_input('Write configuration to slot %i of YubiKey? [y/N] : ' % slot)
        if user_input.lower() in ('y', 'ye', 'yes'):
            y_key.write_config(cfg, slot=slot)
            print "\nSuccess!"
            print "Status  : %s " % y_key.status()
        else:
            print "\nAborted"
            return 0

        raw_input("Press enter to update...")

        cfg = y_key.init_config(update=True)
        cfg.ticket_flag('APPEND_CR', False)

        print "Updating..."
        y_key.write_config(cfg, slot=slot)
        print "\nSuccess!"
    except yubico.yubico_exception.YubicoError as inst:
        print "ERROR: %s" % inst.reason
        return 2

if __name__ == '__main__':
    sys.exit(main())
