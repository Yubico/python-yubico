"""
module for creating frames of data that can be sent to a YubiKey
"""
# Copyright (c) 2010, Yubico AB
# See the file COPYING for licence statement.

__all__ = [
    # constants
    # functions
    # classes
    'YubiKeyFrame',
]

import struct

from . import yubico_util
from . import yubikey_defs
from . import yubico_exception
from .yubico_version import __version__

from .yubikey_defs import SLOT

class YubiKeyFrame:
    """
    Class containing an YKFRAME (as defined in ykdef.h).

    A frame is basically 64 bytes of data. When this is to be sent
    to a YubiKey, it is put inside 10 USB HID feature reports. Each
    feature report is 7 bytes of data plus 1 byte of sequencing and
    flags.
    """

    def __init__(self, command, payload=b''):
        if not payload:
            payload = b'\x00' * 64
        if len(payload) != 64:
            raise yubico_exception.InputError('payload must be empty or 64 bytes')
        if not isinstance(payload, bytes):
            raise yubico_exception.InputError('payload must be a bytestring')
        self.payload = payload
        self.command = command
        self.crc = yubico_util.crc16(payload)

    def __repr__(self):
        return '<%s.%s instance at %s: %s>' % (
            self.__class__.__module__,
            self.__class__.__name__,
            hex(id(self)),
            self.command
            )

    def to_string(self):
        """
        Return the frame as a 70 byte string.
        """
        # From ykdef.h :
        #
        # // Frame structure
	# #define SLOT_DATA_SIZE  64
        # typedef struct {
        #     unsigned char payload[SLOT_DATA_SIZE];
        #     unsigned char slot;
        #     unsigned short crc;
        #     unsigned char filler[3];
        # } YKFRAME;
        filler = b''
        return struct.pack('<64sBH3s',
                           self.payload, self.command, self.crc, filler)

    def to_feature_reports(self, debug=False):
        """
        Return the frame as an array of 8-byte parts, ready to be sent to a YubiKey.
        """
        rest = self.to_string()
        seq = 0
        out = []
        # When sending a frame to the YubiKey, we can (should) remove any
        # 7-byte serie that only consists of '\x00', besides the first
        # and last serie.
        while rest:
            this, rest = rest[:7], rest[7:]
            if seq > 0 and rest:
                # never skip first or last serie
                if this != b'\x00\x00\x00\x00\x00\x00\x00':
                    this += yubico_util.chr_byte(yubikey_defs.SLOT_WRITE_FLAG + seq)
                    out.append(self._debug_string(debug, this))
            else:
                this += yubico_util.chr_byte(yubikey_defs.SLOT_WRITE_FLAG + seq)
                out.append(self._debug_string(debug, this))
            seq += 1
        return out

    def _debug_string(self, debug, data):
        """
        Annotate a frames data, if debug is True.
        """
        if not debug:
            return data
        if self.command in [
            SLOT.CONFIG,
            SLOT.CONFIG2,
            SLOT.UPDATE1,
            SLOT.UPDATE2,
            SLOT.SWAP,
        ]:
            # annotate according to config_st (see yubikey_defs.to_string())
            if yubico_util.ord_byte(data[-1]) == 0x80:
                return (data, "FFFFFFF")
            if yubico_util.ord_byte(data[-1]) == 0x81:
                return (data, "FFFFFFF")
            if yubico_util.ord_byte(data[-1]) == 0x82:
                return (data, "FFUUUUU")
            if yubico_util.ord_byte(data[-1]) == 0x83:
                return (data, "UKKKKKK")
            if yubico_util.ord_byte(data[-1]) == 0x84:
                return (data, "KKKKKKK")
            if yubico_util.ord_byte(data[-1]) == 0x85:
                return (data, "KKKAAAA")
            if yubico_util.ord_byte(data[-1]) == 0x86:
                return (data, "AAlETCr")
            if yubico_util.ord_byte(data[-1]) == 0x87:
                return (data, "rCR")
            # after payload
            if yubico_util.ord_byte(data[-1]) == 0x89:
                return (data, " Scr")
        else:
            return (data, '')
