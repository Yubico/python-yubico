"""
utility functions used in yubikey_config.
"""
# Copyright (c) 2010, 2012 Yubico AB
# See the file COPYING for licence statement.

__all__ = [
    # constants
    # functions
    # classes
    'YubiKeyConfigBits',
    'YubiKeyConfigFlag',
    'YubiKeyExtendedFlag',
    'YubiKeyTicketFlag',
]


class YubiKeyFlag(object):
    """
    A flag value, and associated metadata.
    """

    def __init__(self, key, value, doc=None, min_ykver=(0, 0), max_ykver=None, models=['YubiKey', 'YubiKey NEO', 'YubiKey 4']):
        """
        Metadata about a ticket/config/extended flag bit.

        @param key: Name of flag, such as 'APPEND_CR'
        @param value: Bit value, 0x20 for APPEND_CR
        @param doc: Human readable description of flag
        @param min_ykver: Tuple with the minimum version required (major, minor,)
        @param min_ykver: Tuple with the maximum version required (major, minor,) (for depreacted flags)
        @param models: List of model identifiers (strings) that support this flag
        """
        if type(key) is not str:
            assert()
        if type(value) is not int:
            assert()
        if type(min_ykver) is not tuple:
            assert()
        if type(models) is not list:
            assert()

        self.key = key
        self.value = value
        self.doc = doc
        self.min_ykver = min_ykver
        self.max_ykver = max_ykver
        self.models = models

        return None

    def __repr__(self):
        return '<%s instance at %s: %s (0x%x)>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.key,
            self.value
            )

    def is_equal(self, key):
        """ Check if key is equal to that of this instance """
        return self.key == key

    def to_integer(self):
        """ Return flag value """
        return self.value

    def req_version(self):
        """ Return the minimum required version """
        return self.min_ykver

    def req_string(self, model):
        """ Return string describing model and version requirement. """
        if model not in self.models:
            model = self.models
        if self.min_ykver and self.max_ykver:
            return "%s %d.%d..%d.%d" % (model, \
                                           self.min_ykver[0], self.min_ykver[1], \
                                           self.max_ykver[0], self.max_ykver[1], \
                                           )
        if self.max_ykver:
            return "%s <= %d.%d" % (model, self.max_ykver[0], self.max_ykver[1])

        return "%s >= %d.%d" % (model, self.min_ykver[0], self.min_ykver[1])

    def is_compatible(self, model, version):
        """ Check if this flag is compatible with a YubiKey of version 'ver'. """
        if not model in self.models:
            return False
        if self.max_ykver:
            return (version >= self.min_ykver and
                    version <= self.max_ykver)
        else:
            return version >= self.min_ykver


class YubiKeyTicketFlag(YubiKeyFlag):
    """
    A ticket flag value, and associated metadata.
    """


class YubiKeyConfigFlag(YubiKeyFlag):
    """
    A config flag value, and associated metadata.
    """

    def __init__(self, key, value, mode='', doc=None, min_ykver=(0, 0), max_ykver=None):
        if type(mode) is not str:
            assert()
        self.mode = mode

        super(YubiKeyConfigFlag, self).__init__(key, value, doc=doc, min_ykver=min_ykver, max_ykver=max_ykver)


class YubiKeyExtendedFlag(YubiKeyFlag):
    """
    An extended flag value, and associated metadata.
    """

    def __init__(self, key, value, mode='', doc=None, min_ykver=(2, 2), max_ykver=None):
        if type(mode) is not str:
            assert()
        self.mode = mode

        super(YubiKeyExtendedFlag, self).__init__(key, value, doc=doc, min_ykver=min_ykver, max_ykver=max_ykver)


class YubiKeyConfigBits(object):
    """
    Class to hold bit values for configuration.
    """
    def __init__(self, default=0x0):
        self.value = default
        return None

    def __repr__(self):
        return '<%s instance at %s: value 0x%x>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.value,
            )

    def get_set(self, flag, new):
        """
        Return the boolean value of 'flag'. If 'new' is set,
        the flag is updated, and the value before update is
        returned.
        """
        old = self._is_set(flag)
        if new is True:
            self._set(flag)
        elif new is False:
            self._clear(flag)
        return old

    def to_integer(self):
        """ Return the sum of all flags as an integer. """
        return self.value

    def _is_set(self, flag):
        """ Check if flag is set. Returns True or False. """
        return self.value & flag == flag

    def _set(self, flag):
        """ Set flag. """
        self.value |= flag

    def _clear(self, flag):
        """ Clear flag. """
        self.value &= (0xff - flag)
