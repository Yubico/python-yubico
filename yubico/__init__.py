"""
the yubico package

See http://www.yubico.com/yubikey/ for information about the YubiKey.

Example usage :

  import yubico

  try:
      YK = yubico.find_yubikey(debug=True)
      print "Version : %s " % YK.version()
  except yubico.yubico_exception.YubicoError as e:
      print "ERROR: %s" % e.reason
      sys.exit(1)

To learn about configuring your YubiKey using this framework, see the
yubikey_config module.
"""
# Copyright (c) 2010, 2011, 2012 Yubico AB
# See the file COPYING for licence statement.

from .yubico_version import __version__

__all__ = [
    # classes
    'YubiKey',
    # functions
    "find_yubikey",
    # modules
    "yubico_exception",
    "yubico_util",
    "yubikey",
    "yubikey_config",
    "yubikey_config_util",
    "yubikey_defs",
    "yubikey_frame",
    "yubikey_usb_hid",
    "yubikey_neo_usb_hid",
    ]

# to not have to import yubico.yubikey
from .yubikey import YubiKey
from .yubikey import find_key as find_yubikey
