#!/usr/bin/env python

from setuptools import setup
from release import release

setup(
    name='python-yubico',
    version='1.2.1',
    description='Python code for talking to Yubico\'s YubiKeys',
    author='Fredrik Thulin',
    author_email='fredrik@yubico.com',
    maintainer='Yubico Open Source Maintainers',
    maintainer_email='ossmaint@yubico.com',
    url='https://github.com/Yubico/python-yubico',
    license='BSD 2 clause',
    packages=['yubico'],
    install_requires=['pyusb'],
    setup_requires=['nose>=1.0'],
    test_suite='nose.collector',
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
