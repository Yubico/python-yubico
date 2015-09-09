"""
module for accessing a USB HID YubiKey 4
"""

# Copyright (c) 2012 Yubico AB
# See the file COPYING for licence statement.

__all__ = [
    # constants
    # functions
    # classes
    'YubiKey4_USBHID',
    'YubiKey4_USBHIDError'
]

from .yubikey_defs import SLOT, MODE, YK4_CAPA
from . import yubikey_frame
from . import yubikey_base
from . import yubico_exception
from . import yubico_util
from . import yubikey_neo_usb_hid

MODE_CAPABILITIES = {  # Required capabilities to support USB mode.
    MODE.OTP           : [YK4_CAPA.OTP],
    MODE.CCID          : [YK4_CAPA.CCID],
    MODE.OTP_CCID      : [YK4_CAPA.OTP, YK4_CAPA.CCID],
    MODE.U2F           : [YK4_CAPA.U2F],
    MODE.OTP_U2F       : [YK4_CAPA.OTP, YK4_CAPA.U2F],
    MODE.U2F_CCID      : [YK4_CAPA.U2F, YK4_CAPA.CCID],
    MODE.OTP_U2F_CCID  : [YK4_CAPA.OTP, YK4_CAPA.U2F, YK4_CAPA.CCID]
}


class YubiKey4_USBHIDError(yubico_exception.YubicoError):
    """ Exception raised for errors with the YK4 USB HID communication. """


class YubiKey4_USBHIDCapabilities(yubikey_neo_usb_hid.YubiKeyNEO_USBHIDCapabilities):
    """
    Capabilities of current YubiKey 4.
    """
    _yk4_capa = 0

    def _set_yk4_capa(self, yk4_capa):
        int_val = 0
        for b in yk4_capa:
            int_val <<= 8
            int_val += yubico_util.ord_byte(b)
        self._yk4_capa = int_val

    def have_nfc_ndef(self, slot=1):
        return False

    def have_usb_mode(self, mode):
        mode &= ~MODE.FLAG_EJECT  # Mask away eject flag
        if self.version < (4, 1, 0):  # YK Plus is locked in OTP+U2F
            return mode == MODE.OTP_U2F
        for cap_req in MODE_CAPABILITIES.get(mode, [0]):
            if not self.have_capability(cap_req):
                return False
        return True

    def have_capabilities(self):
        return self.version >= (4, 1, 0)

    def have_capability(self, capability):
        return self._yk4_capa & capability != 0


class YubiKey4_USBHID(yubikey_neo_usb_hid.YubiKeyNEO_USBHID):
    """
    Class for accessing a YubiKey 4 over USB HID.

    """

    model = 'YubiKey 4'
    description = 'YubiKey 4'
    _capabilities_cls = YubiKey4_USBHIDCapabilities

    def __init__(self, debug=False, skip=0, hid_device=None):
        """
        Find and connect to a YubiKey 4 (USB HID).

        Attributes :
            skip  -- number of YubiKeys to skip
            debug -- True or False
        """
        super(YubiKey4_USBHID, self).__init__(debug, skip, hid_device)
        if self.version_num() < (4, 0, 0):
            raise yubikey_base.YubiKeyVersionError(
                "Incorrect version for YubiKey 4 %s" % self.version())
        elif self.version_num() < (4, 1, 0):
            self.description = 'YubiKey Plus'
        elif self.version_num() < (4, 2, 0):
            self.description = 'YubiKey Edge/Edge-n'

        if self.capabilities.have_capabilities():
            data = yubico_util.tlv_parse(self._read_capabilities())
            self.capabilities._set_yk4_capa(data.get(YK4_CAPA.TAG.CAPA, b''))

    def _read_capabilities(self):
        """ Read the capabilities list from a YubiKey >= 4.0.0 """

        frame = yubikey_frame.YubiKeyFrame(command=SLOT.YK4_CAPABILITIES)
        self._device._write(frame)
        response = self._device._read_response()
        r_len = ord(response[0])

        # 1 byte length, 2 byte CRC.
        if not yubico_util.validate_crc16(response[:r_len+3]):
            raise YubiKey4_USBHIDError("Read from device failed CRC check")

        return response[1:r_len+1]
