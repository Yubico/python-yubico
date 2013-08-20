"""
module for accessing a USB HID YubiKey
"""

# Copyright (c) 2010, 2011, 2012 Yubico AB
# See the file COPYING for licence statement.

__all__ = [
  # constants
  # functions
  # classes
  'YubiKeyUSBHID',
  'YubiKeyUSBHIDError',
  'YubiKeyUSBHIDStatus',
]

from yubico import __version__

import yubico_util
import yubico_exception
import yubikey_frame
import yubikey_config
import yubikey_defs
import yubikey
from yubikey import YubiKey
import struct
import time
import sys

# Various USB/HID parameters
_USB_TYPE_CLASS		= (0x01 << 5)
_USB_RECIP_INTERFACE	= 0x01
_USB_ENDPOINT_IN	= 0x80
_USB_ENDPOINT_OUT	= 0x00

_HID_GET_REPORT		= 0x01
_HID_SET_REPORT		= 0x09

_USB_TIMEOUT_MS		= 100

# from ykcore_backend.h
_FEATURE_RPT_SIZE	= 8
_REPORT_TYPE_FEATURE	= 0x03
# from ykdef.h
_YUBICO_VID		= 0x1050
_YUBIKEY_PID		= 0x0010
_NEO_OTP_PID 		= 0x0110
_NEO_OTP_CCID_PID 	= 0x0111
# commands from ykdef.h
_SLOT_DEVICE_SERIAL	= 0x10 # Device serial number
_SLOT_CHAL_OTP1		= 0x20 # Write 6 byte challenge to slot 1, get Yubico OTP response
_SLOT_CHAL_OTP2		= 0x28 # Write 6 byte challenge to slot 2, get Yubico OTP response
_SLOT_CHAL_HMAC1	= 0x30 # Write 64 byte challenge to slot 1, get HMAC-SHA1 response
_SLOT_CHAL_HMAC2	= 0x38 # Write 64 byte challenge to slot 2, get HMAC-SHA1 response

# dict used to select command for mode+slot in _challenge_response
_CMD_CHALLENGE = {'HMAC': {1: _SLOT_CHAL_HMAC1, 2: _SLOT_CHAL_HMAC2},
                  'OTP': {1: _SLOT_CHAL_OTP1, 2: _SLOT_CHAL_OTP2},
                  }

class YubiKeyUSBHIDError(yubico_exception.YubicoError):
    """ Exception raised for errors with the USB HID communication. """

class YubiKeyUSBHIDCapabilities(yubikey.YubiKeyCapabilities):
    """
    Capture the capabilities of the various versions of YubiKeys.

    Overrides just the functions from YubiKeyCapabilities() that are available
    in one or more versions, leaving the other ones at False through default_answer.
    """
    def __init__(self, model, version, default_answer):
        yubikey.YubiKeyCapabilities.__init__(self, model = model, \
                                                 version = version, \
                                                 default_answer = default_answer)

    def have_yubico_OTP(self):
        """ Yubico OTP support has always been available in the standard YubiKey. """
        return True

    def have_OATH(self, mode):
        """ OATH HOTP was introduced in YubiKey 2.2. """
        if mode not in ['HOTP']:
            return False
        return (self.version >= (2, 1, 0,))

    def have_challenge_response(self, mode):
        """ Challenge-response was introduced in YubiKey 2.2. """
        if mode not in ['HMAC', 'OTP']:
            return False
        return (self.version >= (2, 2, 0,))

    def have_serial_number(self):
        """ Reading serial number was introduced in YubiKey 2.2, but depends on extflags set too. """
        return (self.version >= (2, 2, 0,))

    def have_ticket_flag(self, flag):
        return flag.is_compatible(model = self.model, version = self.version)

    def have_config_flag(self, flag):
        return flag.is_compatible(model = self.model, version = self.version)

    def have_extended_flag(self, flag):
        return flag.is_compatible(model = self.model, version = self.version)

    def have_extended_scan_code_mode(self):
        return (self.version >= (2, 0, 0,))

    def have_shifted_1_mode(self):
        return (self.version >= (2, 0, 0,))

    def have_configuration_slot(self, slot):
        return (slot in [1, 2])

class YubiKeyUSBHID(YubiKey):
    """
    Class for accessing a YubiKey over USB HID.

    This class is for communicating specifically with standard YubiKeys
    (USB vendor id = 0x1050, product id = 0x10) using USB HID.

    There is another class for the YubiKey NEO BETA, even though that
    product also goes by product id 0x10 for the BETA versions. The
    expectation is that the final YubiKey NEO will have it's own product id.

    Tested with YubiKey versions 1.3 and 2.2.
    """

    model = 'YubiKey'
    description = 'YubiKey (or YubiKey NANO)'

    def __init__(self, debug=False, skip=0):
        """
        Find and connect to a YubiKey (USB HID).

        Attributes :
            skip  -- number of YubiKeys to skip
            debug -- True or False
        """
        YubiKey.__init__(self, debug)
        self._usb_handle = None
        if not self._open(skip):
            raise YubiKeyUSBHIDError('YubiKey USB HID initialization failed')
        self.status()
        self.capabilities = \
            YubiKeyUSBHIDCapabilities(model = self.model, \
                                          version = self.version_num(), \
                                          default_answer = False)

    def __del__(self):
        try:
            if self._usb_handle:
                self._close()
        except IOError:
            pass

    def __repr__(self):
        return '<%s instance at %s: YubiKey version %s>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.version()
            )

    def status(self):
        """
        Poll YubiKey for status.
        """
        data = self._read()
        self._status = YubiKeyUSBHIDStatus(data)
        return self._status

    def version_num(self):
        """ Get the YubiKey version as a tuple (major, minor, build). """
        return self._status.ykver()

    def version(self):
        """ Get the YubiKey version. """
        return self._status.version()

    def serial(self, may_block=True):
        """ Get the YubiKey serial number (requires YubiKey 2.2). """
        if not self.capabilities.have_serial_number():
            raise yubikey.YubiKeyVersionError("Serial number unsupported in YubiKey %s" % self.version() )
        return self._read_serial(may_block)

    def challenge_response(self, challenge, mode='HMAC', slot=1, variable=True, may_block=True):
        """ Issue a challenge to the YubiKey and return the response (requires YubiKey 2.2). """
        if not self.capabilities.have_challenge_response(mode):
            raise yubikey.YubiKeyVersionError("%s challenge-response unsupported in YubiKey %s" % (mode, self.version()) )
        return self._challenge_response(challenge, mode, slot, variable, may_block)

    def init_config(self, **kw):
        """ Get a configuration object for this type of YubiKey. """
        return YubiKeyConfigUSBHID(ykver=self.version_num(), \
                                       capabilities = self.capabilities, \
                                       **kw)

    def write_config(self, cfg, slot=1):
        """ Write a configuration to the YubiKey. """
        cfg_req_ver = cfg.version_required()
        if cfg_req_ver > self.version_num():
            raise yubikey.YubiKeyVersionError('Configuration requires YubiKey version %i.%i (this is %s)' % \
                                                  (cfg_req_ver[0], cfg_req_ver[1], self.version()))
        if not self.capabilities.have_configuration_slot(slot):
            raise YubiKeyUSBHIDError("Can't write configuration to slot %i" % (slot))
        return self._write_config(cfg, slot)

    def _read_serial(self, may_block):
        """ Read the serial number from a YubiKey > 2.2. """

        frame = yubikey_frame.YubiKeyFrame(command = _SLOT_DEVICE_SERIAL)
        self._write(frame)
        response = self._read_response(may_block=may_block)
        if not yubico_util.validate_crc16(response[:6]):
            raise YubiKeyUSBHIDError("Read from device failed CRC check")
        # the serial number is big-endian, although everything else is little-endian
        serial = struct.unpack('>lxxx', response)
        return serial[0]

    def _challenge_response(self, challenge, mode, slot, variable, may_block):
        """ Do challenge-response with a YubiKey > 2.0. """
         # Check length and pad challenge if appropriate
        if mode == 'HMAC':
            if len(challenge) > yubikey_defs.SHA1_MAX_BLOCK_SIZE:
                raise yubico_exception.InputError('Mode HMAC challenge too big (%i/%i)' \
                                                      % (yubikey_defs.SHA1_MAX_BLOCK_SIZE, len(challenge)))
            if len(challenge) < yubikey_defs.SHA1_MAX_BLOCK_SIZE:
                pad_with = chr(0x0)
                if variable and challenge[-1] == pad_with:
                    pad_with = chr(0xff)
                challenge = challenge.ljust(yubikey_defs.SHA1_MAX_BLOCK_SIZE, pad_with)
            response_len = yubikey_defs.SHA1_DIGEST_SIZE
        elif mode == 'OTP':
            if len(challenge) != yubikey_defs.UID_SIZE:
                raise yubico_exception.InputError('Mode OTP challenge must be %i bytes (got %i)' \
                                                      % (yubikey_defs.UID_SIZE, len(challenge)))
            challenge = challenge.ljust(yubikey_defs.SHA1_MAX_BLOCK_SIZE, chr(0x0))
            response_len = 16
        else:
            raise yubico_exception.InputError('Invalid mode supplied (%s, valid values are HMAC and OTP)' \
                                                  % (mode))

        try:
            command = _CMD_CHALLENGE[mode][slot]
        except:
            raise yubico_exception.InputError('Invalid slot specified (%s)' % (slot))

        frame = yubikey_frame.YubiKeyFrame(command=command, payload=challenge)
        self._write(frame)
        response = self._read_response(may_block=may_block)
        if not yubico_util.validate_crc16(response[:response_len + 2]):
            raise YubiKeyUSBHIDError("Read from device failed CRC check")
        return response[:response_len]

    def _write_config(self, cfg, slot):
        """ Write configuration to YubiKey. """
        old_pgm_seq = self._status.pgm_seq
        frame = cfg.to_frame(slot=slot)
        self._debug("Writing %s frame :\n%s\n" % \
                        (yubikey_config.command2str(frame.command), cfg))
        self._write(frame)
        self._waitfor_clear(yubikey_defs.SLOT_WRITE_FLAG)
        # make sure we have a fresh pgm_seq value
        self.status()
        self._debug("Programmed slot %i, sequence %i -> %i\n" % (slot, old_pgm_seq, self._status.pgm_seq))
        if self._status.pgm_seq != old_pgm_seq + 1:
            raise YubiKeyUSBHIDError('YubiKey programming failed (seq %i not increased (%i))' % \
                                         (old_pgm_seq, self._status.pgm_seq))

    def _read_response(self, may_block=False):
        """ Wait for a response to become available, and read it. """
        # wait for response to become available
        res = self._waitfor_set(yubikey_defs.RESP_PENDING_FLAG, may_block)[:7]
        # continue reading while response pending is set
        while True:
            this = self._read()
            flags = ord(this[7])
            if flags & yubikey_defs.RESP_PENDING_FLAG:
                seq = flags & 0b00011111
                if res and (seq == 0):
                    break
                res += this[:7]
            else:
                break
        self._write_reset()
        return res

    def _read(self):
        """ Read a USB HID feature report from the YubiKey. """
        request_type = _USB_TYPE_CLASS | _USB_RECIP_INTERFACE | _USB_ENDPOINT_IN
        value = _REPORT_TYPE_FEATURE << 8	# apparently required for YubiKey 1.3.2, but not 2.2.x
        recv = self._usb_handle.controlMsg(request_type,
                                          _HID_GET_REPORT,
                                          _FEATURE_RPT_SIZE,
                                          value = value,
                                          timeout = _USB_TIMEOUT_MS)
        if len(recv) != _FEATURE_RPT_SIZE:
            self._debug("Failed reading %i bytes (got %i) from USB HID YubiKey.\n"
                        % (_FEATURE_RPT_SIZE, recv))
            raise YubiKeyUSBHIDError('Failed reading from USB HID YubiKey')
        data = ''.join(chr(c) for c in recv)
        self._debug("READ  : %s" % (yubico_util.hexdump(data, colorize=True)))
        return data

    def _write(self, frame):
        """
        Write a YubiKeyFrame to the USB HID.

        Includes polling for YubiKey readiness before each write.
        """
        for data in frame.to_feature_reports(debug=self.debug):
            debug_str = None
            if self.debug:
                (data, debug_str) = data
            # first, we ensure the YubiKey will accept a write
            self._waitfor_clear(yubikey_defs.SLOT_WRITE_FLAG)
            self._raw_write(data, debug_str)
        return True

    def _write_reset(self):
        """
        Reset read mode by issuing a dummy write.
        """
        data = '\x00\x00\x00\x00\x00\x00\x00\x8f'
        self._raw_write(data)
        self._waitfor_clear(yubikey_defs.SLOT_WRITE_FLAG)
        return True

    def _raw_write(self, data, debug_str = None):
        """
        Write data to YubiKey.
        """
        if self.debug:
            if not debug_str:
                debug_str = ''
            hexdump = yubico_util.hexdump(data, colorize=True)[:-1] # strip LF
            self._debug("WRITE : %s %s\n" % (hexdump, debug_str))
        request_type = _USB_TYPE_CLASS | _USB_RECIP_INTERFACE | _USB_ENDPOINT_OUT
        value = _REPORT_TYPE_FEATURE << 8	# apparently required for YubiKey 1.3.2, but not 2.2.x
        sent = self._usb_handle.controlMsg(request_type,
                                          _HID_SET_REPORT,
                                          data,
                                          value = value,
                                          timeout = _USB_TIMEOUT_MS)
        if sent != _FEATURE_RPT_SIZE:
            self.debug("Failed writing %i bytes (wrote %i) to USB HID YubiKey.\n"
                       % (_FEATURE_RPT_SIZE, sent))
            raise YubiKeyUSBHIDError('Failed talking to USB HID YubiKey')
        return sent

    def _waitfor_clear(self, mask, may_block=False):
        """
        Wait for the YubiKey to turn OFF the bits in 'mask' in status responses.

        Returns the 8 bytes last read.
        """
        return self._waitfor('nand', mask, may_block)

    def _waitfor_set(self, mask, may_block=False):
        """
        Wait for the YubiKey to turn ON the bits in 'mask' in status responses.

        Returns the 8 bytes last read.
        """
        return self._waitfor('and', mask, may_block)

    def _waitfor(self, mode, mask, may_block, timeout=2):
        """
        Wait for the YubiKey to either turn ON or OFF certain bits in the status byte.

        mode is either 'and' or 'nand'
        timeout is a number of seconds (precision about ~0.5 seconds)
        """
        finished = False
        sleep = 0.01
        # After six sleeps, we've slept 0.64 seconds.
        wait_num = (timeout * 2) - 1 + 6
        resp_timeout = False	# YubiKey hasn't indicated RESP_TIMEOUT (yet)
        while not finished:
            this = self._read()
            flags = ord(this[7])

            if flags & yubikey_defs.RESP_TIMEOUT_WAIT_FLAG:
                if not resp_timeout:
                    resp_timeout = True
                    seconds_left = flags & yubikey_defs.RESP_TIMEOUT_WAIT_MASK
                    self._debug("Device indicates RESP_TIMEOUT (%i seconds left)\n" \
                                    % (seconds_left))
                    if may_block:
                        # calculate new wait_num - never more than 20 seconds
                        seconds_left = min(20, seconds_left)
                        wait_num = (seconds_left * 2) - 1 + 6

            if mode is 'nand':
                if not flags & mask == mask:
                    finished = True
                else:
                    self._debug("Status %s (0x%x) has not cleared bits %s (0x%x)\n"
                                % (bin(flags), flags, bin(mask), mask))
            elif mode is 'and':
                if flags & mask == mask:
                    finished = True
                else:
                    self._debug("Status %s (0x%x) has not set bits %s (0x%x)\n"
                                % (bin(flags), flags, bin(mask), mask))
            else:
                assert()

            if not finished:
                wait_num -= 1
                if wait_num == 0:
                    if mode is 'nand':
                        reason = 'Timed out waiting for YubiKey to clear status 0x%x' % mask
                    else:
                        reason = 'Timed out waiting for YubiKey to set status 0x%x' % mask
                    raise yubikey.YubiKeyTimeout(reason)
                time.sleep(sleep)
                sleep = min(sleep + sleep, 0.5)
            else:
                return this

    def _open(self, skip=0):
        """ Perform HID initialization """
        usb_device = self._get_usb_device(skip)

        if usb_device:
            usb_conf = usb_device.configurations[0]
            self._usb_int = usb_conf.interfaces[0][0]
        else:
            raise YubiKeyUSBHIDError('No USB YubiKey found')

        try:
            self._usb_handle = usb_device.open()
            self._usb_handle.detachKernelDriver(0)
        except Exception, error:
            if 'could not detach kernel driver from interface' in str(error):
                self._debug('The in-kernel-HID driver has already been detached\n')
            else:
                self._debug("detachKernelDriver not supported!")

        self._usb_handle.setConfiguration(1)
        self._usb_handle.claimInterface(self._usb_int)
        return True

    def _close(self):
        """
        Release the USB interface again.
        """
        self._usb_handle.releaseInterface()
        try:
            # If we're using PyUSB >= 1.0 we can re-attach the kernel driver here.
            self._usb_handle.dev.attach_kernel_driver(0)
        except:
            pass
        self._usb_int = None
        self._usb_handle = None
        return True

    def _get_usb_device(self, skip=0):
        """
        Get YubiKey USB device.

        Optionally allows you to skip n devices, to support multiple attached YubiKeys.
        """
        try:
            # PyUSB >= 1.0, this is a workaround for a problem with libusbx
            # on Windows.
            import usb.core
            import usb.legacy
            devices = [usb.legacy.Device(d) for d in usb.core.find(
                find_all=True, idVendor=_YUBICO_VID)]
        except ImportError:
            # Using PyUsb < 1.0.
            import usb
            devices = [d for bus in usb.busses() for d in bus.devices]
        for device in devices:
            if device.idVendor == _YUBICO_VID:
                if device.idProduct in [_YUBIKEY_PID, _NEO_OTP_PID, _NEO_OTP_CCID_PID]:
                    if skip == 0:
                        return device
                    skip -= 1
        return None

    def _debug(self, out, print_prefix=True):
        """ Print out to stderr, if debugging is enabled. """
        if self.debug:
            if print_prefix:
                pre = self.__class__.__name__
                if hasattr(self, 'debug_prefix'):
                    pre = getattr(self, 'debug_prefix')
                sys.stderr.write("%s: " % (self.__class__.__name__))
            sys.stderr.write(out)

class YubiKeyUSBHIDStatus():
    """ Class to represent the status information we get from the YubiKey. """

    CONFIG1_VALID = 0x01 # Bit in touchLevel indicating that configuration 1 is valid (from firmware 2.1)
    CONFIG2_VALID = 0x02 # Bit in touchLevel indicating that configuration 2 is valid (from firmware 2.1)

    def __init__(self, data):
        # From ykdef.h :
        #
        # struct status_st {
        #        unsigned char versionMajor;     /* Firmware version information */
        #        unsigned char versionMinor;
        #        unsigned char versionBuild;
        #        unsigned char pgmSeq;           /* Programming sequence number. 0 if no valid configuration */
        #        unsigned short touchLevel;      /* Level from touch detector */
        # };
        fmt = '<x BBB B H B'
        self.version_major, \
            self.version_minor, \
            self.version_build, \
            self.pgm_seq, \
            self.touch_level, \
            self.flags = struct.unpack(fmt, data)

    def __repr__(self):
        valid_str = ''
        flags_str = ''
        if self.ykver() >= (2,1,0):
            valid_str = ", valid=%s" % (self.valid_configs())
        if self.flags:
            flags_str = " (flags 0x%x)" % (self.flags)
        return '<%s instance at %s: YubiKey version %s, pgm_seq=%i, touch_level=%i%s%s>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.version(),
            self.pgm_seq,
            self.touch_level,
            valid_str,
            flags_str,
            )


    def ykver(self):
        """ Returns a tuple with the (major, minor, build) version of the YubiKey firmware. """
        return (self.version_major, self.version_minor, self.version_build)

    def version(self):
        """ Return the YubiKey firmware version as a string. """
        version = "%d.%d.%d" % (self.ykver())
        return version

    def valid_configs(self):
        """ Return a list of slots having a valid configurtion. Requires firmware 2.1. """
        if self.ykver() < (2,1,0):
            raise YubiKeyUSBHIDError('Valid configs unsupported in firmware %s' % (self.version()))
        res = []
        if self.touch_level & self.CONFIG1_VALID == self.CONFIG1_VALID:
            res.append(1)
        if self.touch_level & self.CONFIG2_VALID == self.CONFIG2_VALID:
            res.append(2)
        return res

class YubiKeyConfigUSBHID(yubikey_config.YubiKeyConfig):
    """
    Configuration class for USB HID YubiKeys.
    """
    def __init__(self, ykver, capabilities = None, **kw):
        yubikey_config.YubiKeyConfig.__init__(self, ykver = ykver, capabilities = capabilities, **kw)
        return None
