"""
module for configuring YubiKeys
"""
# Copyright (c) 2010, 2012 Yubico AB
# See the file COPYING for licence statement.

__all__ = [
    # constants
    'TicketFlags',
    'ConfigFlags',
    'ExtendedFlags',
    # functions
    # classes
    'YubiKeyConfigError',
    'YubiKeyConfig',
]

from .yubico_version import __version__

import sys
import struct
import binascii
from . import yubico_util
from . import yubikey_defs
from . import yubikey_frame
from . import yubico_exception
from . import yubikey_base
from .yubikey_config_util import YubiKeyConfigBits, YubiKeyConfigFlag, YubiKeyExtendedFlag, YubiKeyTicketFlag
from .yubikey_defs import SLOT


def command2str(num):
    """ Turn command number into name """
    for attr in SLOT.__dict__.keys():
        if not attr.startswith('_') and attr == attr.upper():
            if getattr(SLOT, attr) == num:
                return 'SLOT_%s' % attr

    return "0x%02x" % (num)

### BEGIN DEPRECATED
### These are here for backwards compatibility, DO NOT USE!
SLOT_CONFIG  = SLOT.CONFIG
SLOT_CONFIG2 = SLOT.CONFIG2
SLOT_UPDATE1 = SLOT.UPDATE1
SLOT_UPDATE2 = SLOT.UPDATE2
SLOT_SWAP    = SLOT.SWAP
### END DEPRECATED


TicketFlags = [
    YubiKeyTicketFlag('TAB_FIRST',		0x01, min_ykver=(1, 0), doc='Send TAB before first part'),
    YubiKeyTicketFlag('APPEND_TAB1',		0x02, min_ykver=(1, 0), doc='Send TAB after first part'),
    YubiKeyTicketFlag('APPEND_TAB2',		0x04, min_ykver=(1, 0), doc='Send TAB after second part'),
    YubiKeyTicketFlag('APPEND_DELAY1',		0x08, min_ykver=(1, 0), doc='Add 0.5s delay after first part'),
    YubiKeyTicketFlag('APPEND_DELAY2',		0x10, min_ykver=(1, 0), doc='Add 0.5s delay after second part'),
    YubiKeyTicketFlag('APPEND_CR',		0x20, min_ykver=(1, 0), doc='Append CR as final character'),
    YubiKeyTicketFlag('OATH_HOTP',		0x40, min_ykver=(2, 1), doc='Choose OATH-HOTP mode'),
    YubiKeyTicketFlag('CHAL_RESP',		0x40, min_ykver=(2, 2), doc='Choose Challenge-Response mode'),
    YubiKeyTicketFlag('PROTECT_CFG2',		0x80, min_ykver=(2, 0), doc='Protect configuration in slot 2'),
    ]

ConfigFlags = [
    YubiKeyConfigFlag('SEND_REF',		0x01, min_ykver=(1, 0), doc='Send reference string (0..F) before data'),
    YubiKeyConfigFlag('TICKET_FIRST',		0x02, min_ykver=(1, 0), doc='Send ticket first (default is fixed part)', max_ykver=(1, 9)),
    YubiKeyConfigFlag('PACING_10MS',		0x04, min_ykver=(1, 0), doc='Add 10ms intra-key pacing'),
    YubiKeyConfigFlag('PACING_20MS',		0x08, min_ykver=(1, 0), doc='Add 20ms intra-key pacing'),
    #YubiKeyConfigFlag('ALLOW_HIDTRIG',		0x10, min_ykver=(1, 0), doc='DONT USE: Allow trigger through HID/keyboard', max_ykver=(1, 9)),
    YubiKeyConfigFlag('STATIC_TICKET',		0x20, min_ykver=(1, 0), doc='Static ticket generation'),

    # YubiKey 2.0 and above
    YubiKeyConfigFlag('SHORT_TICKET',		0x02, min_ykver=(2, 0), doc='Send truncated ticket (half length)'),
    YubiKeyConfigFlag('STRONG_PW1',		0x10, min_ykver=(2, 0), doc='Strong password policy flag #1 (mixed case)'),
    YubiKeyConfigFlag('STRONG_PW2',		0x40, min_ykver=(2, 0), doc='Strong password policy flag #2 (subtitute 0..7 to digits)'),
    YubiKeyConfigFlag('MAN_UPDATE',		0x80, min_ykver=(2, 0), doc='Allow manual (local) update of static OTP'),

    # YubiKey 2.1 and above
    YubiKeyConfigFlag('OATH_HOTP8',		0x02, min_ykver=(2, 1), mode='OATH', doc='Generate 8 digits HOTP rather than 6 digits'),
    YubiKeyConfigFlag('OATH_FIXED_MODHEX1',	0x10, min_ykver=(2, 1), mode='OATH', doc='First byte in fixed part sent as modhex'),
    YubiKeyConfigFlag('OATH_FIXED_MODHEX2',	0x40, min_ykver=(2, 1), mode='OATH', doc='First two bytes in fixed part sent as modhex'),
    YubiKeyConfigFlag('OATH_FIXED_MODHEX',	0x50, min_ykver=(2, 1), mode='OATH', doc='Fixed part sent as modhex'),
    YubiKeyConfigFlag('OATH_FIXED_MASK',	0x50, min_ykver=(2, 1), mode='OATH', doc='Mask to get out fixed flags'),

    # YubiKey 2.2 and above
    YubiKeyConfigFlag('CHAL_YUBICO',		0x20, min_ykver=(2, 2), mode='CHAL', doc='Challenge-response enabled - Yubico OTP mode'),
    YubiKeyConfigFlag('CHAL_HMAC',		0x22, min_ykver=(2, 2), mode='CHAL', doc='Challenge-response enabled - HMAC-SHA1'),
    YubiKeyConfigFlag('HMAC_LT64',		0x04, min_ykver=(2, 2), mode='CHAL', doc='Set when HMAC message is less than 64 bytes'),
    YubiKeyConfigFlag('CHAL_BTN_TRIG',		0x08, min_ykver=(2, 2), mode='CHAL', doc='Challenge-respoonse operation requires button press'),
    ]

ExtendedFlags = [
    YubiKeyExtendedFlag('SERIAL_BTN_VISIBLE',	0x01, min_ykver=(2, 2), doc='Serial number visible at startup (button press)'),
    YubiKeyExtendedFlag('SERIAL_USB_VISIBLE',	0x02, min_ykver=(2, 2), doc='Serial number visible in USB iSerial field'),
    YubiKeyExtendedFlag('SERIAL_API_VISIBLE',	0x04, min_ykver=(2, 2), doc='Serial number visible via API call'),

    # YubiKey 2.3 and above
    YubiKeyExtendedFlag('USE_NUMERIC_KEYPAD',	0x08, min_ykver=(2, 3), doc='Use numeric keypad for digits'),
    YubiKeyExtendedFlag('FAST_TRIG',		0x10, min_ykver=(2, 3), doc='Use fast trig if only cfg1 set'),
    YubiKeyExtendedFlag('ALLOW_UPDATE',		0x20, min_ykver=(2, 3), doc='Allow update of existing configuration (selected flags + access code)'),
    YubiKeyExtendedFlag('DORMANT',		0x40, min_ykver=(2, 3), doc='Dormant configuration (can be woken up and flag removed = requires update flag)'),
    ]


class YubiKeyConfigError(yubico_exception.YubicoError):
    """
    Exception raised for YubiKey configuration errors.
    """


class YubiKeyConfig(object):
    """
    Base class for configuration of all current types of YubiKeys.
    """
    def __init__(self, ykver=None, capabilities=None, update=False, swap=False,
                 zap=False):
        """
        `ykver' is a tuple (major, minor) with the version number of the key
        you are planning to apply this configuration to. Not mandated, but
        will get you an exception when trying to set flags for example, rather
        than the YubiKey just not operating as expected after programming.

        YubiKey >= 2.3 supports updating certain parts of a configuration
        (for example turning on/off APPEND_CR) without overwriting others
        (most notably the stored secret). Set `update' to True if this is
        what you want. The current programming must have flag 'ALLOW_UPDATE'
        set to allow configuration update instead of requiring complete
        reprogramming.

        YubiKey >= 2.3 also supports swapping the configurations, making
        slot 1 be slot 2 and vice versa. Set swap=True for this.

        YubiKeys support deleting a configuration, setting it in an
        unprogrammed state. Set zap=True for this.
        """
        if capabilities is None:
            self.capabilities = yubikey_base.YubiKeyCapabilities(default_answer = True)
        else:
            self.capabilities = capabilities

        # Minimum version of YubiKey this configuration will require
        self.yk_req_version = (0, 0)
        self.ykver = ykver

        self.fixed = b''
        self.uid = b''
        self.key = b''
        self.access_code = b''

        self.ticket_flags = YubiKeyConfigBits(0x0)
        self.config_flags = YubiKeyConfigBits(0x0)
        self.extended_flags = YubiKeyConfigBits(0x0)

        self.unlock_code = b''
        self._mode = ''
        if update or swap:
            self._require_version(major=2, minor=3)
        self._update_config = update
        self._swap_slots = swap
        self._zap = zap

        return None

    def __repr__(self):
        return '<%s instance at %s: mode %s, v=%s/%s, lf=%i, lu=%i, lk=%i, lac=%i, tf=%x, cf=%x, ef=%x, lu=%i, up=%s, sw=%s, z=%s>' % (
            self.__class__.__name__,
            hex(id(self)),
            self._mode,
            self.yk_req_version, self.ykver,
            len(self.fixed),
            len(self.uid),
            len(self.key),
            len(self.access_code),
            self.ticket_flags.to_integer(),
            self.config_flags.to_integer(),
            self.extended_flags.to_integer(),
            len(self.unlock_code),
            self._update_config,
            self._swap_slots,
            self._zap
            )

    def version_required(self):
        """
        Return the (major, minor) versions of YubiKey required for this configuration.
        """
        return self.yk_req_version

    def fixed_string(self, data=None):
        """
        The fixed string is used to identify a particular Yubikey device.

        The fixed string is referred to as the 'Token Identifier' in OATH-HOTP mode.

        The length of the fixed string can be set between 0 and 16 bytes.

        Tip: This can also be used to extend the length of a static password.
        """
        old = self.fixed
        if data != None:
            new = self._decode_input_string(data)
            if len(new) <= 16:
                self.fixed = new
            else:
                raise yubico_exception.InputError('The "fixed" string must be 0..16 bytes')
        return old

    def enable_extended_scan_code_mode(self):
        """
        Extended scan code mode means the Yubikey will output the bytes in
        the 'fixed string' as scan codes, without modhex encoding the data.

        Because of the way this is stored in the config flags, it is not
        possible to disable this option once it is enabled (of course, you
        can abort config update or reprogram the YubiKey again).

        Requires YubiKey 2.x.
        """
        if not self.capabilities.have_extended_scan_code_mode():
            raise
        self._require_version(major=2)
        self.config_flag('SHORT_TICKET', True)
        self.config_flag('STATIC_TICKET', False)

    def enable_shifted_1(self):
        """
        This will cause a shifted character 1 (typically '!') to be sent before
        anything else. This can be used to make the YubiKey output qualify as a
        password with 'special characters', if such is required.

        Because of the way this is stored in the config flags, it is not
        possible to disable this option once it is enabled (of course, you
        can abort config update or reprogram the YubiKey again).

        Requires YubiKey 2.x.
        """
        self._require_version(major=2)
        self.config_flag('STRONG_PW2', True)
        self.config_flag('SEND_REF', True)

    def aes_key(self, data):
        """
        AES128 key to program into YubiKey.

        Supply data as either a raw string, or a hexlified string prefixed by 'h:'.
        The result, after any hex decoding, must be 16 bytes.
        """
        old = self.key
        if data:
            new = self._decode_input_string(data)
            if len(new) == 16:
                self.key = new
            else:
                raise yubico_exception.InputError('AES128 key must be exactly 16 bytes')

        return old

    def unlock_key(self, data):
        """
        Access code to allow re-programming of your YubiKey.

        Supply data as either a raw bytestring, or a hexlified bytestring prefixed by 'h:'.
        The result, after any hex decoding, must be 6 bytes.
        """
        if data.startswith(b'h:'):
            new = binascii.unhexlify(data[2:])
        else:
            new = data
        if len(new) == 6:
            self.unlock_code = new
            if not self.access_code:
                # Don't reset the access code when programming, unless that seems
                # to be the intent of the calling program.
                self.access_code = new
        else:
            raise yubico_exception.InputError('Unlock key must be exactly 6 bytes')

    def access_key(self, data):
        """
        Set a new access code which will be required for future re-programmings of your YubiKey.

        Supply data as either a raw string, or a hexlified string prefixed by 'h:'.
        The result, after any hex decoding, must be 6 bytes.
        """
        if data.startswith(b'h:'):
            new = binascii.unhexlify(data[2:])
        else:
            new = data
        if len(new) == 6:
            self.access_code = new
        else:
            raise yubico_exception.InputError('Access key must be exactly 6 bytes')

    def mode_yubikey_otp(self, private_uid, aes_key):
        """
        Set the YubiKey up for standard OTP validation.
        """
        if not self.capabilities.have_yubico_OTP():
            raise yubikey_base.YubiKeyVersionError('Yubico OTP not available in %s version %d.%d' \
                                                   % (self.capabilities.model, self.ykver[0], self.ykver[1]))
        if private_uid.startswith(b'h:'):
            private_uid = binascii.unhexlify(private_uid[2:])
        if len(private_uid) != yubikey_defs.UID_SIZE:
            raise yubico_exception.InputError('Private UID must be %i bytes' % (yubikey_defs.UID_SIZE))

        self._change_mode('YUBIKEY_OTP', major=0, minor=9)
        self.uid = private_uid
        self.aes_key(aes_key)

    def mode_oath_hotp(self, secret, digits=6, factor_seed=None, omp=0x0, tt=0x0, mui=''):
        """
        Set the YubiKey up for OATH-HOTP operation.

        Requires YubiKey 2.1.
        """
        if not self.capabilities.have_OATH('HOTP'):
            raise yubikey_base.YubiKeyVersionError('OATH HOTP not available in %s version %d.%d' \
                                                   % (self.capabilities.model, self.ykver[0], self.ykver[1]))
        if digits != 6 and digits != 8:
            raise yubico_exception.InputError('OATH-HOTP digits must be 6 or 8')

        self._change_mode('OATH_HOTP', major=2, minor=1)
        self._set_20_bytes_key(secret)
        if digits == 8:
            self.config_flag('OATH_HOTP8', True)
        if omp or tt or mui:
            decoded_mui = self._decode_input_string(mui)
            fixed = yubico_util.chr_byte(omp) + yubico_util.chr_byte(tt) + decoded_mui
            self.fixed_string(fixed)
        if factor_seed:
            self.uid = self.uid + struct.pack('<H', factor_seed)

    def mode_challenge_response(self, secret, type='HMAC', variable=True, require_button=False):
        """
        Set the YubiKey up for challenge-response operation.

        `type' can be 'HMAC' or 'OTP'.

        `variable' is only applicable to type 'HMAC'.

        For type HMAC, `secret' is expected to be 20 bytes (160 bits).
        For type OTP, `secret' is expected to be 16 bytes (128 bits).

        Requires YubiKey 2.2.
        """
        if not type.upper() in ['HMAC', 'OTP']:
            raise yubico_exception.InputError('Invalid \'type\' (%s)' % type)
        if not self.capabilities.have_challenge_response(type.upper()):
            raise yubikey_base.YubiKeyVersionError('%s Challenge-Response not available in %s version %d.%d' \
                                                   % (type.upper(), self.capabilities.model, \
                                                          self.ykver[0], self.ykver[1]))
        self._change_mode('CHAL_RESP', major=2, minor=2)
        if type.upper() == 'HMAC':
            self.config_flag('CHAL_HMAC', True)
            self.config_flag('HMAC_LT64', variable)
            self._set_20_bytes_key(secret)
        else:
            # type is 'OTP', checked above
            self.config_flag('CHAL_YUBICO', True)
            self.aes_key(secret)
        self.config_flag('CHAL_BTN_TRIG', require_button)

    def ticket_flag(self, which, new=None):
        """
        Get or set a ticket flag.

        'which' can be either a string ('APPEND_CR' etc.), or an integer.
        You should ALWAYS use a string, unless you really know what you are doing.
        """
        flag = _get_flag(which, TicketFlags)
        if flag:
            if not self.capabilities.have_ticket_flag(flag):
                raise yubikey_base.YubiKeyVersionError('Ticket flag %s requires %s, and this is %s %d.%d'
                                                       % (which, flag.req_string(self.capabilities.model), \
                                                         self.capabilities.model, self.ykver[0], self.ykver[1]))
            req_major, req_minor = flag.req_version()
            self._require_version(major=req_major, minor=req_minor)
            value = flag.to_integer()
        else:
            if type(which) is not int:
                raise yubico_exception.InputError('Unknown non-integer TicketFlag (%s)' % which)
            value = which

        return self.ticket_flags.get_set(value, new)

    def config_flag(self, which, new=None):
        """
        Get or set a config flag.

        'which' can be either a string ('PACING_20MS' etc.), or an integer.
        You should ALWAYS use a string, unless you really know what you are doing.
        """
        flag = _get_flag(which, ConfigFlags)
        if flag:
            if not self.capabilities.have_config_flag(flag):
                raise yubikey_base.YubiKeyVersionError('Config flag %s requires %s, and this is %s %d.%d'
                                                       % (which, flag.req_string(self.capabilities.model), \
                                                         self.capabilities.model, self.ykver[0], self.ykver[1]))
            req_major, req_minor = flag.req_version()
            self._require_version(major=req_major, minor=req_minor)
            value = flag.to_integer()
        else:
            if type(which) is not int:
                raise yubico_exception.InputError('Unknown non-integer ConfigFlag (%s)' % which)
            value = which

        return self.config_flags.get_set(value, new)

    def extended_flag(self, which, new=None):
        """
        Get or set a extended flag.

        'which' can be either a string ('SERIAL_API_VISIBLE' etc.), or an integer.
        You should ALWAYS use a string, unless you really know what you are doing.
        """
        flag = _get_flag(which, ExtendedFlags)
        if flag:
            if not self.capabilities.have_extended_flag(flag):
                raise yubikey_base.YubiKeyVersionError('Extended flag %s requires %s, and this is %s %d.%d'
                                                       % (which, flag.req_string(self.capabilities.model), \
                                                         self.capabilities.model, self.ykver[0], self.ykver[1]))
            req_major, req_minor = flag.req_version()
            self._require_version(major=req_major, minor=req_minor)
            value = flag.to_integer()
        else:
            if type(which) is not int:
                raise yubico_exception.InputError('Unknown non-integer ExtendedFlag (%s)' % which)
            value = which

        return self.extended_flags.get_set(value, new)

    def to_string(self):
        """
        Return the current configuration as a bytestring (always 64 bytes).
        """
        #define UID_SIZE		6	/* Size of secret ID field */
        #define FIXED_SIZE              16      /* Max size of fixed field */
        #define KEY_SIZE                16      /* Size of AES key */
        #define KEY_SIZE_OATH           20      /* Size of OATH-HOTP key (key field + first 4 of UID field) */
        #define ACC_CODE_SIZE           6       /* Size of access code to re-program device */
        #
        #struct config_st {
        #    unsigned char fixed[FIXED_SIZE];/* Fixed data in binary format */
        #    unsigned char uid[UID_SIZE];    /* Fixed UID part of ticket */
        #    unsigned char key[KEY_SIZE];    /* AES key */
        #    unsigned char accCode[ACC_CODE_SIZE]; /* Access code to re-program device */
        #    unsigned char fixedSize;        /* Number of bytes in fixed field (0 if not used) */
        #    unsigned char extFlags;         /* Extended flags */
        #    unsigned char tktFlags;         /* Ticket configuration flags */
        #    unsigned char cfgFlags;         /* General configuration flags */
        #    unsigned char rfu[2];           /* Reserved for future use */
        #    unsigned short crc;             /* CRC16 value of all fields */
        #};
        t_rfu = 0

        first = struct.pack('<16s6s16s6sBBBBH',
                            self.fixed,
                            self.uid,
                            self.key,
                            self.access_code,
                            len(self.fixed),
                            self.extended_flags.to_integer(),
                            self.ticket_flags.to_integer(),
                            self.config_flags.to_integer(),
                            t_rfu
                            )

        crc = 0xffff - yubico_util.crc16(first)

        second = first + struct.pack('<H', crc) + self.unlock_code
        return second

    def to_frame(self, slot=1):
        """
        Return the current configuration as a YubiKeyFrame object.
        """
        data = self.to_string()
        payload = data.ljust(64, yubico_util.chr_byte(0x0))
        if slot is 1:
            if self._update_config:
                command = SLOT.UPDATE1
            else:
                command = SLOT.CONFIG
        elif slot is 2:
            if self._update_config:
                command = SLOT.UPDATE2
            else:
                command = SLOT.CONFIG2
        else:
            assert()

        if self._swap_slots:
            command = SLOT.SWAP

        if self._zap:
            payload = b''

        return yubikey_frame.YubiKeyFrame(command=command, payload=payload)

    def _require_version(self, major, minor=0):
        """ Update the minimum version of YubiKey this configuration can be applied to. """
        new_ver = (major, minor)
        if self.ykver and new_ver > self.ykver:
            raise yubikey_base.YubiKeyVersionError('Configuration requires YubiKey %d.%d, and this is %d.%d'
                                              % (major, minor, self.ykver[0], self.ykver[1]))
        if new_ver > self.yk_req_version:
            self.yk_req_version = new_ver

    def _decode_input_string(self, data):
        if sys.version_info >= (3, 0) and isinstance(data, str):
            data = data.encode('ascii')
        if data.startswith(b'm:'):
            data = b'h:' + yubico_util.modhex_decode(data[2:])
        if data.startswith(b'h:'):
            return(binascii.unhexlify(data[2:]))
        else:
            return(data)

    def _change_mode(self, mode, major, minor):
        """ Change mode of operation, with some sanity checks. """
        if self._mode:
            if self._mode != mode:
                raise RuntimeError('Can\'t change mode (from %s to %s)' % (self._mode, mode))
        self._require_version(major=major, minor=minor)
        self._mode = mode
        # when setting mode, we reset all flags
        self.ticket_flags = YubiKeyConfigBits(0x0)
        self.config_flags = YubiKeyConfigBits(0x0)
        self.extended_flags = YubiKeyConfigBits(0x0)
        if mode != 'YUBIKEY_OTP':
            self.ticket_flag(mode, True)

    def _set_20_bytes_key(self, data):
        """
        Set a 20 bytes key. This is used in CHAL_HMAC and OATH_HOTP mode.

        Supply data as either a raw bytestring, or a hexlified bytestring prefixed by 'h:'.
        The result, after any hex decoding, must be 20 bytes.
        """
        if data.startswith(b'h:'):
            new = binascii.unhexlify(data[2:])
        else:
            new = data
        if len(new) == 20:
            self.key = new[:16]
            self.uid = new[16:]
        else:
            raise yubico_exception.InputError('HMAC key must be exactly 20 bytes')


def _get_flag(which, flags):
    """ Find 'which' entry in 'flags'. """
    res = [this for this in flags if this.is_equal(which)]
    if len(res) == 0:
        return None
    if len(res) == 1:
        return res[0]
    assert()
