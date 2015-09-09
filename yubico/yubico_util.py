"""
utility functions for Yubico modules
"""
# Copyright (c) 2010, Yubico AB
# See the file COPYING for licence statement.

__all__ = [
    # constants
    # functions
    'crc16',
    'validate_crc16',
    'hexdump',
    'modhex_decode',
    'hotp_truncate',
    # classes
]

import sys
import string

from .yubico_version import __version__
from . import yubikey_defs
from . import yubico_exception

_CRC_OK_RESIDUAL = 0xf0b8

def ord_byte(byte):
    """Convert a byte to its integer value"""
    if sys.version_info < (3, 0):
        return ord(byte)
    else:
        # In Python 3, single bytes are represented as integers
        return int(byte)

def chr_byte(number):
    """Convert an integer value to a length-1 bytestring"""
    if sys.version_info < (3, 0):
        return chr(number)
    else:
        return bytes([number])

def crc16(data):
    """
    Calculate an ISO13239 CRC checksum of the input buffer (bytestring).
    """
    m_crc = 0xffff
    for this in data:
        m_crc ^= ord_byte(this)
        for _ in range(8):
            j = m_crc & 1
            m_crc >>= 1
            if j:
                m_crc ^= 0x8408
    return m_crc

def validate_crc16(data):
    """
    Validate that the CRC of the contents of buffer is the residual OK value.

    The input is a bytestring.
    """
    return crc16(data) == _CRC_OK_RESIDUAL


class DumpColors:
    """ Class holding ANSI colors for colorization of hexdump output """

    def __init__(self):
        self.colors = {'BLUE': '\033[94m',
                       'GREEN': '\033[92m',
                       'RESET': '\033[0m',
                       }
        self.enabled = True
        return None

    def get(self, what):
        """
        Get the ANSI code for 'what'

        Returns an empty string if disabled/not found
        """
        if self.enabled:
            if what in self.colors:
                return self.colors[what]
        return ''

    def enable(self):
        """ Enable colorization """
        self.enabled = True

    def disable(self):
        """ Disable colorization """
        self.enabled = False

def hexdump(src, length=8, colorize=False):
    """ Produce a string hexdump of src, for debug output.

    Input: bytestring; output: text string
    """
    if not src:
        return str(src)
    if type(src) is not bytes:
        raise yubico_exception.InputError('Hexdump \'src\' must be bytestring (got %s)' % type(src))
    offset = 0
    result = ''
    for this in group(src, length):
        if colorize:
            last, this = this[-1], this[:-1]
            colors = DumpColors()
            color = colors.get('RESET')
            if ord_byte(last) & yubikey_defs.RESP_PENDING_FLAG:
                # write to key
                color = colors.get('BLUE')
            elif ord_byte(last) & yubikey_defs.SLOT_WRITE_FLAG:
                color = colors.get('GREEN')
            hex_s = color + ' '.join(["%02x" % ord_byte(x) for x in this]) + colors.get('RESET')
            hex_s += " %02x" % ord_byte(last)
        else:
            hex_s = ' '.join(["%02x" % ord_byte(x) for x in this])
        result += "%04X   %s\n" % (offset, hex_s)
        offset += length
    return result

def group(data, num):
    """ Split data into chunks of num chars each """
    return [data[i:i+num] for i in range(0, len(data), num)]

def modhex_decode(data):
    """ Convert a modhex bytestring to ordinary hex. """
    try:
        maketrans = string.maketrans
    except AttributeError:
        # Python 3
        maketrans = bytes.maketrans
    t_map = maketrans(b"cbdefghijklnrtuv", b"0123456789abcdef")
    return data.translate(t_map)

def hotp_truncate(hmac_result, length=6):
    """ Perform the HOTP Algorithm truncating.

    Input is a bytestring.
    """
    if len(hmac_result) != 20:
        raise yubico_exception.YubicoError("HMAC-SHA-1 not 20 bytes long")
    offset   =  ord_byte(hmac_result[19]) & 0xf
    bin_code = (ord_byte(hmac_result[offset]) & 0x7f) << 24 \
        | (ord_byte(hmac_result[offset+1]) & 0xff) << 16 \
        | (ord_byte(hmac_result[offset+2]) & 0xff) <<  8 \
        | (ord_byte(hmac_result[offset+3]) & 0xff)
    return bin_code % (10 ** length)

def tlv_parse(data):
    """ Parses a bytestring of TLV values into a dict with the tags as keys."""
    parsed = {}
    while data:
        t, l, data = ord_byte(data[0]), ord_byte(data[1]), data[2:]
        parsed[t], data = data[:l], data[l:]
    return parsed
