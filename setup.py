#!/usr/bin/env python

from setuptools import setup
from release import release
import re

VERSION_PATTERN = re.compile(r"(?m)^__version__\s*=\s*['\"](.+)['\"]$")


def get_version():
    """Return the current version as defined by yubico/yubico_version.py."""

    with open('yubico/yubico_version.py', 'r') as f:
        match = VERSION_PATTERN.search(f.read())
        return match.group(1)


setup(
    name='python-yubico',
    description='Python code for talking to Yubico\'s YubiKeys',
    version=get_version(),
    author='Dain Nilsson',  # Original author: Fredrik Thulin
    author_email='dain@yubico.com',
    maintainer='Yubico Open Source Maintainers',
    maintainer_email='ossmaint@yubico.com',
    url='https://github.com/Yubico/python-yubico',
    license='BSD 2 clause',
    packages=['yubico'],
    install_requires=['pyusb'],
    test_suite='test',
    cmdclass={'release': release},
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
    ]
)
