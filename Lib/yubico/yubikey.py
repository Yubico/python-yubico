"""
module for accessing a YubiKey

In an attempt to support any future versions of the YubiKey which
might not be USB HID devices, you should always use the yubikey.find_key()
(or better yet, yubico.find_yubikey()) function to initialize
communication with YubiKeys.

Example usage (if using this module directly, see base module yubico) :

    import yubico.yubikey

    try:
        YK = yubico.yubikey.find_key()
        print "Version : %s " % YK.version()
    except yubico.yubico_exception.YubicoError as inst:
        print "ERROR: %s" % inst.reason
"""
# Copyright (c) 2010, 2011 Yubico AB
# See the file COPYING for licence statement.

__all__ = [
    # constants
    'RESP_TIMEOUT_WAIT_FLAG',
    'RESP_PENDING_FLAG',
    'SLOT_WRITE_FLAG',
    # functions
    'find_key',
    # classes
    'YubiKey',
    'YubiKeyTimeout',
]

from yubico  import __version__
import yubico_exception

class YubiKeyError(yubico_exception.YubicoError):
    """
    Exception raised concerning YubiKey operations.

    Attributes:
        reason -- explanation of the error
    """
    def __init__(self, reason='no details'):
        yubico_exception.YubicoError.__init__(self, reason)

class YubiKeyTimeout(YubiKeyError):
    """
    Exception raised when a YubiKey operation timed out.

    Attributes:
        reason -- explanation of the error
    """
    def __init__(self, reason='no details'):
        YubiKeyError.__init__(self, reason)


class YubiKey():
    """
    Base class for accessing YubiKeys
    """

    def __init__(self, debug):
        self.debug = debug
        return None

    def __del__(self):
        return None

    def version(self):
        """ Get the connected YubiKey's version as a string. """
        pass

    def serial(self, may_block=True):
        """
        Get the connected YubiKey's serial number.

        Note that since version 2.?.? this requires the YubiKey to be
        configured with the extended flag SERIAL_API_VISIBLE.

        If the YubiKey is configured with SERIAL_BTN_VISIBLE set to True,
        it will start blinking and require a button press before revealing
        the serial number, with a 15 seconds timeout. Set `may_block'
        to False to abort if this is the case.
        """
        pass

    def challenge(self, challenge, mode='HMAC', slot=1, variable=True, may_block=True):
        """
        Get the response to a challenge from a connected YubiKey.

        `mode' is either 'HMAC' or 'OTP'.
        `slot' is 1 or 2.
        `variable' is only relevant for mode == HMAC.

        If variable is True, challenge will be padded such that the
        YubiKey will compute the HMAC as if there were no padding.
        If variable is False, challenge will always be NULL-padded
        to 64 bytes.

        The special case of no input will be HMACed by the YubiKey
        (in variable HMAC mode) as data = 0x00, length = 1.

        In mode 'OTP', the challenge should be exactly 6 bytes. The
        response will be a YubiKey "ticket" with the 6-byte challenge
        in the ticket.uid field. The rest of the "ticket" will contain
        timestamp and counter information, so two identical challenges
        will NOT result in the same responses. The response is
        decryptable using AES ECB if you have access to the AES key
        programmed into the YubiKey.
        """
        pass

    def init_config(self):
        """
        Return a YubiKey configuration object for this type of YubiKey.
        """
        pass

    def write_config(self, cfg, slot):
        """
        Configure a YubiKey using a configuration object.
        """
        pass

# Since YubiKeyUSBHID is a subclass of YubiKey (defined here above),
# the import must be after the declaration of YubiKey. We also carefully
# import only what we need to not get a circular import of modules.
from yubikey_usb_hid import YubiKeyUSBHID, YubiKeyUSBHIDError

def find_key(debug=False, skip=0):
    """
    Locate a connected YubiKey. Throws an exception if none is found.

    This function is supposed to be possible to extend if any other YubiKeys
    appear in the future.

    Attributes :
        skip  -- number of YubiKeys to skip
        debug -- True or False
    """
    try:
        return YubiKeyUSBHID(debug=debug, skip=skip)
    except YubiKeyUSBHIDError as inst:
        if 'No USB YubiKey found' in str(inst):
            # generalize this error
            raise YubiKeyError('No YubiKey found')
        else:
            raise
