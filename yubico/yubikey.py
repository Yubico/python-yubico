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
# Copyright (c) 2010, 2011, 2012 Yubico AB
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

from .yubico_version  import __version__
from .yubikey_base import YubiKeyError, YubiKeyTimeout, YubiKeyVersionError, YubiKeyCapabilities, YubiKey
from .yubikey_usb_hid import YubiKeyUSBHID, YubiKeyHIDDevice, YubiKeyUSBHIDError
from .yubikey_neo_usb_hid import YubiKeyNEO_USBHID
from .yubikey_4_usb_hid import YubiKey4_USBHID


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
        hid_device = YubiKeyHIDDevice(debug, skip)
        yk_version = hid_device.status().ykver()
        if (2, 1, 4) <= yk_version <= (2, 1, 9):
            return YubiKeyNEO_USBHID(debug, skip, hid_device)
        if yk_version < (3, 0, 0):
            return YubiKeyUSBHID(debug, skip, hid_device)
        if yk_version < (4, 0, 0):
            return YubiKeyNEO_USBHID(debug, skip, hid_device)
        return YubiKey4_USBHID(debug, skip, hid_device)
    except YubiKeyUSBHIDError as inst:
        if 'No USB YubiKey found' in str(inst):
            # generalize this error
            raise YubiKeyError('No YubiKey found')
        else:
            raise
