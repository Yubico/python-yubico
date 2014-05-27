Python package for talking to YubiKeys.

Authors: Fredrik Thulin <fredrik@yubico.com>,
         Dain Nilsson <dain@yubico.com>

Copyright (c) 2011-2013 Yubico AB

See the file [COPYING](COPYING) for licence statement.


Introduction
============

The YubiKey is a hardware token for authentication. The main
mode of the YubiKey is entering a one time password (or a strong
static password) by acting as a USB HID device, but there are
things one can do with bi-directional communication.

1) Configuration. The yubikey_config class should be a feature-wise complete implementation of everything that can be configured on YubiKeys version 1.3 to 2.2 (besides deprecated functions in YubiKey 1.x). See [examples/configure\_nist\_test\_key.py](examples/configure_nist_test_key.py) for an example.

2) Challenge-response. YubiKey 2.2 supports HMAC-SHA1 or Yubico challenge-response operations. See [examples/nist\_challenge\_response.py](examples/nist_challenge_response.py) for an example.


Example
=======

Here is a trivial usage example :


```python
#!/usr/bin/env python
""" Get version of connected YubiKey. """

import sys
import yubico
debug = False

try:
    YK = yubico.find_yubikey(debug=debug)
    print "Version : %s " % YK.version()
except yubico.yubico_exception.YubicoError as inst:
    print "ERROR: %s" % inst.reason
    sys.exit(1)

```

Installation
============

python-yubico is installable in the standard-python way :

    cd python-yubico-$ver
    python setup.py install

This requires the python-setuptools (well, the package is called
that in Debian/Ubuntu). You will also need the Python USB package
from [here](http://pyusb.berlios.de/) - package called python-usb in
Debian/Ubuntu. Note that while both the 0.4 branch and the 1.0
branch are supported, the older 0.4 branch doesn't support 
re-attaching the kernel device driver on close, which will leave
the YubiKey in a state where it is unable to output OTPs until it
has been unplugged and plugged back in again.

If you use a recent Ubuntu release, you should be able to install
python-yubico with these commands :

    sudo add-apt-repository ppa:yubico/stable
    sudo apt-get update
    sudo apt-get install python-yubico

The Launchpad PPA key generated for our packages is 32CBA1A9.

If you use Windows, you will require a PyUSB backend. Python-yubico
has been tested with [libusx](http://libusbx.org/) and confirmed working, 
without the need for replacing the device driver.

Comments
================

Comments, feedback and patches welcome!
