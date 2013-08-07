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
    # functions
    # classes
]

from yubico import __version__

# Yubikey Low level interface #2.3
RESP_TIMEOUT_WAIT_MASK	= 0x1f # Mask to get timeout value
RESP_TIMEOUT_WAIT_FLAG	= 0x20 # Waiting for timeout operation - seconds left in lower 5 bits
RESP_PENDING_FLAG	= 0x40 # Response pending flag
SLOT_WRITE_FLAG		= 0x80 # Write flag - set by app - cleared by device

SHA1_MAX_BLOCK_SIZE	= 64   # Max size of input SHA1 block
SHA1_DIGEST_SIZE	= 20   # Size of SHA1 digest = 160 bits
OTP_CHALRESP_SIZE	= 16   # Number of bytes returned for an Yubico-OTP challenge (not from ykdef.h)

UID_SIZE		= 6    # Size of secret ID field
