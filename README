== python-yubico
Python package for talking to YubiKeys.

=== Introduction
The YubiKey is a hardware token for authentication. The main mode of the
YubiKey is entering a one time password (or a strong static password) by acting
as a USB HID device, but there are things one can do with bi-directional
communication:

1. Configuration. The yubikey_config class should be a feature-wise complete
   implementation of everything that can be configured on YubiKeys version 1.3
   to 3.x (besides deprecated functions in YubiKey 1.x).
   See `examples/configure_nist_test_key` for an example.

2. Challenge-response. YubiKey 2.2 and later supports HMAC-SHA1 or Yubico
   challenge-response operations.
   See `examples/nist_challenge_response` for an example.
   
This library makes it easy to use these two features.

===  Example
Here is a trivial usage example :

[source, python]
----
#!/usr/bin/env python
""" Get version of connected YubiKey. """

import sys
import yubico

try:
    yubikey = yubico.find_yubikey(debug=False)
    print("Version: {}".format(yubikey.version()))
except yubico.yubico_exception.YubicoError as e:
    print("ERROR: {}".format(e.reason))
    sys.exit(1)
----

=== Installation

==== Using the Ubuntu/Debian package manager
If you use a recent Ubuntu release, you should be able to install python-yubico
using apt-get:

  $ sudo apt-get install python3-yubico


==== Using Pip
python-yubico is installable via pip:

  $ pip install python-yubico

==== Using Setup
Or, directly from the source package in the standard Python way:

  $ cd python-yubico-$ver
  $ python setup.py install

This requires the `python-setuptools` package.

=== License
Copyright (c) Yubico AB.
Licensed under the BSD 2-clause license.
See the file COPYING for full licence statement.
