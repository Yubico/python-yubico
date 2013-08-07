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

from yubico import __version__
import yubikey_defs
import yubico_exception
import string

_CRC_OK_RESIDUAL = 0xf0b8

def crc16(data):
    """
    Calculate an ISO13239 CRC checksum of the input buffer.
    """
    m_crc = 0xffff
    for this in data:
        m_crc ^= ord(this)
        for _ in range(8):
            j = m_crc & 1
            m_crc >>= 1
            if j:
                m_crc ^= 0x8408
    return m_crc

def validate_crc16(data):
    """
    Validate that the CRC of the contents of buffer is the residual OK value.
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
    """ Produce a string hexdump of src, for debug output."""
    if not src:
        return str(src)
    if type(src) is not str:
        raise yubico_exception.InputError('Hexdump \'src\' must be string (got %s)' % type(src))
    offset = 0
    result = ''
    for this in group(src, length):
        if colorize:
            last, this = this[-1:], this[:-1]
            colors = DumpColors()
            color = colors.get('RESET')
            if ord(last) & yubikey_defs.RESP_PENDING_FLAG:
                # write to key
                color = colors.get('BLUE')
            elif ord(last) & yubikey_defs.SLOT_WRITE_FLAG:
                color = colors.get('GREEN')
            hex_s = color + ' '.join(["%02x" % ord(x) for x in this]) + colors.get('RESET')
            hex_s += " %02x" % ord(last)
        else:
            hex_s = ' '.join(["%02x" % ord(x) for x in this])
        result += "%04X   %s\n" % (offset, hex_s)
        offset += length
    return result

def group(data, num):
    """ Split data into chunks of num chars each """
    return [data[i:i+num] for i in xrange(0, len(data), num)]

def modhex_decode(data):
    """ Convert a modhex string to ordinary hex. """
    t_map = string.maketrans("cbdefghijklnrtuv", "0123456789abcdef")
    return data.translate(t_map)

def hotp_truncate(hmac_result, length=6):
    """ Perform the HOTP Algorithm truncating. """
    if len(hmac_result) != 20:
        raise yubico_exception.YubicoError("HMAC-SHA-1 not 20 bytes long")
    offset   =  ord(hmac_result[19]) & 0xf
    bin_code = (ord(hmac_result[offset]) & 0x7f) << 24 \
        | (ord(hmac_result[offset+1]) & 0xff) << 16 \
        | (ord(hmac_result[offset+2]) & 0xff) <<  8 \
        | (ord(hmac_result[offset+3]) & 0xff)
    return bin_code % (10 ** length)
