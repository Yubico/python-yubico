# Copyright (c) 2010, 2011, 2012 Yubico AB
# See the file COPYING for licence statement.

from yubico.yubicommon.setup import setup, get_version


setup(
    name='python-yubico',
    description='Python code for talking to Yubico\'s YubiKeys',
    version=get_version('yubico/yubico_version.py'),
    author='Dain Nilsson',  # Original author: Fredrik Thulin
    author_email='dain@yubico.com',
    maintainer='Yubico Open Source Maintainers',
    maintainer_email='ossmaint@yubico.com',
    url='https://github.com/Yubico/python-yubico',
    license='BSD 2 clause',
    packages=['yubico'],
    install_requires=['pyusb'],
    test_suite='test',
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
    ]
)
