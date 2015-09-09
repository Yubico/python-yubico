"""
Module with constants. Many of them from ykdefs.h.
"""
# Copyright (c) 2010, 2011 Yubico AB
# See the file COPYING for licence statement.

__all__ = [
    # constants
    'RESP_TIMEOUT_WAIT_MASK',
    'RESP_TIMEOUT_WAIT_FLAG',
    'RESP_PENDING_FLAG',
    'SLOT_WRITE_FLAG',
    'SHA1_MAX_BLOCK_SIZE',
    'SHA1_DIGEST_SIZE',
    'OTP_CHALRESP_SIZE',
    'UID_SIZE',
    'YUBICO_VID',
    # functions
    # classes
    'SLOT',
    'MODE',
    'PID',
    'YK4_CAPA'
]

from .yubico_version import __version__

# Yubikey Low level interface #2.3
RESP_TIMEOUT_WAIT_MASK	= 0x1f # Mask to get timeout value
RESP_TIMEOUT_WAIT_FLAG	= 0x20 # Waiting for timeout operation - seconds left in lower 5 bits
RESP_PENDING_FLAG	= 0x40 # Response pending flag
SLOT_WRITE_FLAG		= 0x80 # Write flag - set by app - cleared by device

SHA1_MAX_BLOCK_SIZE	= 64   # Max size of input SHA1 block
SHA1_DIGEST_SIZE	= 20   # Size of SHA1 digest = 160 bits
OTP_CHALRESP_SIZE	= 16   # Number of bytes returned for an Yubico-OTP challenge (not from ykdef.h)

UID_SIZE		= 6    # Size of secret ID field


class SLOT(object):
    """Slot entries"""
    CONFIG               = 0x01  # First (default / V1) configuration
    CONFIG2              = 0x03  # Second (V2) configuration

    UPDATE1              = 0x04  # Update slot 1
    UPDATE2              = 0x05  # Update slot 2
    SWAP                 = 0x06  # Swap slot 1 and 2

    NDEF                 = 0x08  # Write NDEF record
    NDEF2                = 0x09  # Write NDEF record for slot 2

    DEVICE_SERIAL        = 0x10  # Device serial number
    DEVICE_CONFIG        = 0x11  # Write device configuration record
    SCAN_MAP             = 0x12  # Write scancode map
    YK4_CAPABILITIES     = 0x13  # Read YK4 capabilities list

    CHAL_OTP1            = 0x20  # Write 6 byte challenge to slot 1, get Yubico OTP response
    CHAL_OTP2            = 0x28  # Write 6 byte challenge to slot 2, get Yubico OTP response

    CHAL_HMAC1           = 0x30  # Write 64 byte challenge to slot 1, get HMAC-SHA1 response
    CHAL_HMAC2           = 0x38  # Write 64 byte challenge to slot 2, get HMAC-SHA1 response


class MODE(object):
    """USB modes"""
    OTP                  = 0x00  # OTP only
    CCID                 = 0x01  # CCID only, no eject
    OTP_CCID             = 0x02  # OTP + CCID composite
    U2F                  = 0x03  # U2F mode
    OTP_U2F              = 0x04  # OTP + U2F composite
    U2F_CCID             = 0x05  # U2F + U2F composite
    OTP_U2F_CCID         = 0x06  # OTP + U2F + CCID composite
    MASK                 = 0x07  # Mask for mode bits
    FLAG_EJECT           = 0x80  # CCID device supports eject (CCID) / OTP force eject (CCID composite)

    @classmethod
    def all(cls, otp=False, ccid=False, u2f=False):
        """Returns a set of all USB modes, with optional filtering"""
        modes = set([
            cls.OTP,
            cls.CCID,
            cls.OTP_CCID,
            cls.U2F,
            cls.OTP_U2F,
            cls.U2F_CCID,
            cls.OTP_U2F_CCID
        ])

        if otp:
            modes.difference_update(set([
                cls.CCID,
                cls.U2F,
                cls.U2F_CCID
            ]))

        if ccid:
            modes.difference_update(set([
                cls.OTP,
                cls.U2F,
                cls.OTP_U2F
            ]))

        if u2f:
            modes.difference_update(set([
                cls.OTP,
                cls.CCID,
                cls.OTP_CCID
            ]))

        return modes


YUBICO_VID               = 0x1050  # Global vendor ID


class PID(object):
    """USB Product IDs"""
    YUBIKEY              = 0x0010  # Yubikey (version 1 and 2)

    NEO_OTP              = 0x0110  # Yubikey NEO - OTP only
    NEO_OTP_CCID         = 0x0111  # Yubikey NEO - OTP and CCID
    NEO_CCID             = 0x0112  # Yubikey NEO - CCID only
    NEO_U2F              = 0x0113  # Yubikey NEO - U2F only
    NEO_OTP_U2F          = 0x0114  # Yubikey NEO - OTP and U2F
    NEO_U2F_CCID         = 0x0115  # Yubikey NEO - U2F and CCID
    NEO_OTP_U2F_CCID     = 0x0116  # Yubikey NEO - OTP, U2F and CCID

    NEO_SKY              = 0x0120  # Security Key by Yubico

    YK4_OTP              = 0x0401  # Yubikey 4 - OTP only
    YK4_U2F              = 0x0402  # Yubikey 4 - U2F only
    YK4_OTP_U2F          = 0x0403  # Yubikey 4 - OTP and U2F
    YK4_CCID             = 0x0404  # Yubikey 4 - CCID only
    YK4_OTP_CCID         = 0x0405  # Yubikey 4 - OTP and CCID
    YK4_U2F_CCID         = 0x0406  # Yubikey 4 - U2F and CCID
    YK4_OTP_U2F_CCID     = 0x0407  # Yubikey 4 - OTP, U2F and CCID

    PLUS_U2F_OTP         = 0x0410  # Yubikey plus - OTP+U2F

    @classmethod
    def all(cls, otp=False, ccid=False, u2f=False):
        """Returns a set of all PIDs, with optional filtering"""
        pids = set([
            cls.YUBIKEY,
            cls.NEO_OTP,
            cls.NEO_OTP_CCID,
            cls.NEO_CCID,
            cls.NEO_U2F,
            cls.NEO_OTP_U2F,
            cls.NEO_U2F_CCID,
            cls.NEO_OTP_U2F_CCID,
            cls.NEO_SKY,
            cls.YK4_OTP,
            cls.YK4_U2F,
            cls.YK4_OTP_U2F,
            cls.YK4_CCID,
            cls.YK4_OTP_CCID,
            cls.YK4_U2F_CCID,
            cls.YK4_OTP_U2F_CCID,
            cls.PLUS_U2F_OTP
        ])

        if otp:
            pids.difference_update(set([
                cls.NEO_CCID,
                cls.NEO_U2F,
                cls.NEO_U2F_CCID,
                cls.NEO_SKY,
                cls.YK4_U2F,
                cls.YK4_CCID,
                cls.YK4_U2F_CCID
            ]))

        if ccid:
            pids.difference_update(set([
                cls.YUBIKEY,
                cls.NEO_OTP,
                cls.NEO_U2F,
                cls.NEO_OTP_U2F,
                cls.NEO_SKY,
                cls.YK4_OTP,
                cls.YK4_U2F,
                cls.YK4_OTP_U2F,
                cls.PLUS_U2F_OTP
            ]))

        if u2f:
            pids.difference_update(set([
                cls.YUBIKEY,
                cls.NEO_OTP,
                cls.NEO_OTP_CCID,
                cls.NEO_CCID,
                cls.YK4_OTP,
                cls.YK4_CCID,
                cls.YK4_OTP_CCID
            ]))

        return pids


class YK4_CAPA(object):
    """Capability bits in the YK4_CAPA field"""
    OTP                  = 0x01  # OTP functionality
    U2F                  = 0x02  # U2F functionality
    CCID                 = 0x04  # CCID functionality

    class TAG(object):
        """Tags for TLV data read from the YK4_CAPABILITIES slot"""
        CAPA             = 0x01  # capabilities
        SERIAL           = 0x02  # serial number
