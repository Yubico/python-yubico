"""
module for Yubikey base classes
"""
# Copyright (c) 2010, 2011, 2012 Yubico AB
# See the file COPYING for licence statement.

from .yubico_version  import __version__
from . import yubico_exception

class YubiKeyError(yubico_exception.YubicoError):
    """
    Exception raised concerning YubiKey operations.

    Attributes:
        reason -- explanation of the error
    """
    def __init__(self, reason='no details'):
        super(YubiKeyError, self).__init__(reason)

class YubiKeyTimeout(YubiKeyError):
    """
    Exception raised when a YubiKey operation timed out.

    Attributes:
        reason -- explanation of the error
    """
    def __init__(self, reason='no details'):
        super(YubiKeyTimeout, self).__init__(reason)

class YubiKeyVersionError(YubiKeyError):
    """
    Exception raised when the YubiKey is not capable of something requested.

    Attributes:
        reason -- explanation of the error
    """
    def __init__(self, reason='no details'):
        super(YubiKeyVersionError, self).__init__(reason)


class YubiKeyCapabilities(object):
    """
    Class expressing the functionality of a YubiKey.

    This base class should be the superset of all sub-classes.

    In this base class, we lie and say 'yes' to all capabilities.

    If the base class is used (such as when creating a YubiKeyConfig()
    before getting a YubiKey()), errors must be handled at runtime
    (or later, when the user is unable to use the YubiKey).
    """

    model = 'Unknown'
    version = (0, 0, 0,)
    version_num = 0x0
    default_answer = True

    def __init__(self, model = None, version = None, default_answer = None):
        self.model = model
        if default_answer is not None:
            self.default_answer = default_answer
        if version is not None:
            self.version = version
            (major, minor, build,) = version
            # convert 2.1.3 to 0x00020103
            self.version_num = (major << 24) | (minor << 16) | build
        return None

    def __repr__(self):
        return '<%s instance at %s: Device %s %s (default: %s)>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.model,
            self.version,
            self.default_answer,
            )

    def have_yubico_OTP(self):
        return self.default_answer

    def have_OATH(self, mode):
        return self.default_answer

    def have_challenge_response(self, mode):
        return self.default_answer

    def have_serial_number(self):
        return self.default_answer

    def have_ticket_flag(self, flag):
        return self.default_answer

    def have_config_flag(self, flag):
        return self.default_answer

    def have_extended_flag(self, flag):
        return self.default_answer

    def have_extended_scan_code_mode(self):
        return self.default_answer

    def have_shifted_1_mode(self):
        return self.default_answer

    def have_nfc_ndef(self, slot=1):
        return self.default_answer

    def have_configuration_slot(self):
        return self.default_answer

    def have_device_config(self):
        return self.default_answer

    def have_usb_mode(self, mode):
        return self.default_answer

    def have_scanmap(self):
        return self.default_answer

    def have_capabilities(self):
        return self.default_answer

    def have_capability(self, capability):
        return self.default_answer


class YubiKey(object):
    """
    Base class for accessing YubiKeys
    """

    debug = None
    capabilities = None

    def __init__(self, debug, capabilities = None):
        self.debug = debug
        if capabilities is None:
            self.capabilities = YubiKeyCapabilities(default_answer = False)
        else:
            self.capabilities = capabilities
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
