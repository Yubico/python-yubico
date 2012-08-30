#!/usr/bin/env python
#
# Copyright (c) 2011, Yubico AB
# See the file COPYING for licence statement.
#
"""
Demonstrate rolling challenges.

This is a scheme for generating "one time" HMAC-SHA1 challenges, which
works by being able to access the HMAC-SHA1 key on the host computer every
time the correct response is provided.

GPGME would've been used to encrypt the HMAC-SHA1 with the next expected
response, but none of the two Python bindings to gpgme I have available
at the moment supports symmetric encryption, so for demo purposes AES CBC
is used instead.
"""

import os
import sys
import json
import hmac
import argparse
import hashlib

import yubico

from Crypto.Cipher import AES

def parse_args():
    """
    Parse the command line arguments
    """
    parser = argparse.ArgumentParser(description = "Demonstrate rolling challenges",
                                     add_help=True
                                     )
    parser.add_argument('-v', '--verbose',
                        dest='verbose',
                        action='store_true', default=False,
                        help='Enable verbose operation.'
                        )
    parser.add_argument('--debug',
                        dest='debug',
                        action='store_true', default=False,
                        help='Enable debug operation.'
                        )
    parser.add_argument('--init',
                        dest='init',
                        action='store_true', default=False,
                        help='Initialize demo.'
                        )
    parser.add_argument('-F', '--filename',
                        dest='filename',
                        required=True,
                        help='State filename.'
                        )
    parser.add_argument('--challenge-length',
                        dest='challenge_length',
                        type = int, default = 32,
                        help='Length of challenges generated, in bytes.'
                        )
    parser.add_argument('--slot',
                        dest='slot',
                        type = int, default = 2,
                        help='YubiKey slot to send challenge to.'
                        )

    args = parser.parse_args()
    return args

def init_demo(args):
    """ Initializes the demo by asking a few questions and creating a new stat file. """
    hmac_key = raw_input("Enter HMAC-SHA1 key as 40 chars of hex (or press enter for random key) : ")
    if hmac_key:
        try:
            hmac_key = hmac_key.decode('hex')
        except:
            sys.stderr.write("Could not decode HMAC-SHA1 key. Please enter 40 hex-chars.\n")
            sys.exit(1)
    else:
        hmac_key = os.urandom(20)
    if len(hmac_key) != 20:
        sys.stderr.write("Decoded HMAC-SHA1 key is %i bytes, expected 20.\n" %( len(hmac_key)))
        sys.exit(1)

    print "To program a YubiKey >= 2.2 for challenge-response with this key, use :"
    print ""
    print "  $ ykpersonalize -%i -ochal-resp -ochal-hmac -ohmac-lt64 -a %s" % (args.slot, hmac_key.encode('hex'))
    print ""

    passphrase = raw_input("Enter the secret passphrase to protect with the rolling challenges : ")

    secret_dict = {"count": 0,
                   "passphrase": passphrase,
                   }
    roll_next_challenge(args, hmac_key, secret_dict)

def do_challenge(args):
    """ Send a challenge to the YubiKey and use the result to decrypt the state file. """
    outer_j = load_state_file(args)
    challenge = outer_j["challenge"]
    print "Challenge : %s" % (challenge)
    response = get_yubikey_response(args, outer_j["challenge"].decode('hex'))
    if args.debug or args.verbose:
        print "\nGot %i bytes response %s\n" % (len(response), response.encode('hex'))
    else:
        print "Response  : %s" % (response.encode('hex'))
    inner_j = decrypt_with_response(args, outer_j["inner"], response)
    if args.verbose or args.debug:
        print "\nDecrypted 'inner' :\n%s\n" % (inner_j)

    secret_dict = {}
    try:
        secret_dict = json.loads(inner_j)
    except ValueError:
        sys.stderr.write("\nCould not parse decoded data as JSON, you probably did not produce the right response.\n")
        sys.exit(1)

    secret_dict["count"] += 1

    print "\nThe passphrase protected using rolling challenges is :\n"
    print "\t%s\n\nAccessed %i times.\n" % (secret_dict["passphrase"], secret_dict["count"])
    roll_next_challenge(args, secret_dict["hmac_key"].decode('hex'), secret_dict)

def get_yubikey_response(args, challenge):
    """
    Do challenge-response with the YubiKey if one is found. Otherwise prompt user to fake a response. """
    try:
        YK = yubico.find_yubikey(debug = args.debug)
        response = YK.challenge_response(challenge.ljust(64, chr(0x0)), slot = args.slot)
        return response
    except yubico.yubico_exception.YubicoError as e:
        print "YubiKey challenge-response failed (%s)" % e.reason
        print ""
    response = raw_input("Assuming you do not have a YubiKey. Enter repsonse manually (hex encoded) : ")
    return response

def roll_next_challenge(args, hmac_key, inner_dict):
    """
    When we have the HMAC-SHA1 key in clear, generate a random challenge and compute the
    expected response for that challenge.
    """
    if len(hmac_key) != 20:
        hmac_key = hmac_key.decode('hex')

    challenge = os.urandom(args.challenge_length)
    response = get_response(hmac_key, challenge)

    print "Generated challenge : %s" % (challenge.encode('hex'))
    print "Expected response   : %s (sssh, don't tell anyone)" % (response)
    print ""
    if args.debug or args.verbose or args.init:
        print "To manually verify that your YubiKey produces this response, use :"
        print ""
        print "  $ ykchalresp -%i -x %s" % (args.slot, challenge.encode('hex'))
        print ""

    inner_dict["hmac_key"] = hmac_key.encode('hex')
    inner_j = json.dumps(inner_dict, indent = 4)
    if args.verbose or args.debug:
        print "Inner JSON :\n%s\n" % (inner_j)
    inner_ciphertext = encrypt_with_response(args, inner_j, response)
    outer_dict = {"challenge": challenge.encode('hex'),
                  "inner": inner_ciphertext,
                  }
    outer_j = json.dumps(outer_dict, indent = 4)
    if args.verbose or args.debug:
        print "\nOuter JSON :\n%s\n" % (outer_j)

    print "Saving 'outer' JSON to file '%s'" % (args.filename)
    write_state_file(args, outer_j)

def get_response(hmac_key, challenge):
    """ Compute the expected response for `challenge'. """
    h = hmac.new(hmac_key, challenge, hashlib.sha1)
    return h.hexdigest()

def encrypt_with_response(args, data, key):
    """
    Encrypt our secret inner data with the response we expect the next time.

    NOTE: The use of AES CBC has not been validated as cryptographically sound
          in this application.

    I would have done this with GPGme if it weren't for the fact that neither
    of the two versions for Python available in Ubuntu 10.10 have support for
    symmetric encrypt/decrypt (LP: #295918).
    """
    # pad data to multiple of 16 bytes for AES CBC
    pad = len(data) % 16
    data += ' ' * (16 - pad)

    # need to pad key as well
    aes_key = key.decode('hex')
    aes_key += chr(0x0) * (32 - len(aes_key))
    if args.debug:
        print ("AES-CBC encrypting 'inner' with key (%i bytes) : %s" % (len(aes_key), aes_key.encode('hex')))

    obj = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = obj.encrypt(data)
    return ciphertext.encode('hex')

def decrypt_with_response(args, data, key):
    """
    Try to decrypt the secret inner data with the response we got to this challenge.
    """
    aes_key = key
    try:
        aes_key = key.decode('hex')
    except TypeError:
        # was not hex encoded
        pass
    # need to pad key
    aes_key += chr(0x0) * (32 - len(aes_key))
    if args.debug:
        print ("AES-CBC decrypting 'inner' using key (%i bytes) : %s" % (len(aes_key), aes_key.encode('hex')))

    obj = AES.new(aes_key, AES.MODE_CBC)
    plaintext = obj.decrypt(data.decode('hex'))
    return plaintext

def write_state_file(args, data):
    """ Save state to file. """
    f = open(args.filename, 'w')
    f.write(data)
    f.close()

def load_state_file(args):
    """ Load (and parse) the state file. """
    return json.loads(open(args.filename).read())

def main():
    args = parse_args()
    if args.init:
        init_demo(args)
    else:
        do_challenge(args)

    print "\nDone\n"

if __name__ == '__main__':
    main()
