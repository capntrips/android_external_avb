#!/usr/bin/env python
#
# Copyright 2018 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
#
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Helper tool for performing an authenticated AVB unlock of an Android Things device.

This tool communicates with an Android Things device over fastboot to perform an
authenticated AVB unlock. The user provides unlock credentials valid for the
device they want to unlock, likely obtained from the Android Things Developer
Console. The tool handles the sequence of fastboot commands to complete the
challenge-response unlock protocol.

Unlock credentials can be provided to the tool in one of two ways:

  1) by providing paths to the individual credential files using the
     '--pik_cert', '--puk_cert', and '--puk' command line swtiches, or
  2) by providing a path to a zip archive containing the three credential files,
     named as follows:
       - Product Intermediate Key (PIK) certificate: 'pik_certificate.*\.bin'
       - Product Unlock Key (PUK) certificate: 'puk_certificate.*\.bin'
       - PUK private key: 'puk.*\.pem'

Dependencies:
  - Python 2.7.x, 3.2.x, or newer (for argparse)
  - PyCrypto 2.5 or newer (for PKCS1_v1_5 and RSA PKCS#8 PEM key import)
  - Android SDK Platform Tools (for fastboot), in PATH
    - https://developer.android.com/studio/releases/platform-tools
"""

HELP_DESCRIPTION = """Performs an authenticated AVB unlock of an Android Things device over
fastboot, given valid unlock credentials for the device."""

HELP_USAGE = """
  %(prog)s [-h] [-v] [-s SERIAL] unlock_creds.zip
  %(prog)s --pik_cert pik_cert.bin --puk_cert puk_cert.bin --puk puk.pem"""

HELP_EPILOG = """examples:
  %(prog)s unlock_creds.zip
  %(prog)s unlock_creds.zip -s SERIAL
  %(prog)s --pik_cert pik_cert.bin --puk_cert puk_cert.bin --puk puk.pem"""

import sys

ver = sys.version_info
if (ver[0] < 2) or (ver[0] == 2 and ver[1] < 7) or (ver[0] == 3 and ver[1] < 2):
  print('This script requires Python 2.7+ or 3.2+')
  sys.exit(1)

import argparse
import contextlib
import os
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile

# Requires PyCrypto 2.5 (or newer) for PKCS1_v1_5 and support for importing
# PEM-encoded RSA keys
try:
  from Crypto.Hash import SHA512
  from Crypto.PublicKey import RSA
  from Crypto.Signature import PKCS1_v1_5
except ImportError as e:
  print('PyCrypto 2.5 or newer required, missing or too old: ' + str(e))


class NullContextManager(object):
  """Local implementation of contextlib.nullcontext, which is Python 3-only."""

  def __init__(self, enter_result=None):
    self.enter_result = enter_result

  def __enter__(self):
    return self.enter_result

  def __exit__(self, *args):
    pass


class UnlockCredentials(object):
  """Helper data container class for the 3 unlock credentials involved in an AVB authenticated unlock operation.

  """

  def __init__(self, intermediate_cert_file, unlock_cert_file, unlock_key_file):
    # The certificates are AvbAtxCertificate structs as defined in libavb_atx,
    # not an X.509 certificate. Do a basic length sanity check when reading
    # them.
    EXPECTED_CERTIFICATE_SIZE = 1620

    with open(intermediate_cert_file, 'rb') as f:
      self._intermediate_cert = f.read()
    if len(self._intermediate_cert) != EXPECTED_CERTIFICATE_SIZE:
      raise ValueError('Invalid intermediate key certificate length.')

    with open(unlock_cert_file, 'rb') as f:
      self._unlock_cert = f.read()
    if len(self._unlock_cert) != EXPECTED_CERTIFICATE_SIZE:
      raise ValueError('Invalid product unlock key certificate length.')

    with open(unlock_key_file, 'rb') as f:
      self._unlock_key = RSA.importKey(f.read())

  @property
  def intermediate_cert(self):
    return self._intermediate_cert

  @property
  def unlock_cert(self):
    return self._unlock_cert

  @property
  def unlock_key(self):
    return self._unlock_key

  @classmethod
  def from_files(cls, pik_cert, puk_cert, puk):
    return NullContextManager(cls(pik_cert, puk_cert, puk))

  @classmethod
  @contextlib.contextmanager
  def from_credential_archive(cls, archive):
    """Create UnlockCredentials from an unlock credential zip archive.

    The zip archive must contain the following three credential files, named as
    follows:
      - Product Intermediate Key (PIK) certificate: 'pik_certificate.*\.bin'
      - Product Unlock Key (PUK) certificate: 'puk_certificate.*\.bin'
      - PUK private key: 'puk.*\.pem'

    This uses @contextlib.contextmanager so we can clean up the tempdir created
    to unpack the zip contents into.

    Arguments:
      - archive: Filename of zip archive containing unlock credentials.

    Raises:
      ValueError: If archive is either missing a required file or contains
      multiple files matching one of the filename formats.
    """

    def _find_one_match(contents, regex, desc):
      r = re.compile(regex)
      matches = list(filter(r.search, contents))
      if not matches:
        raise ValueError(
            "Couldn't find {} file (matching regex '{}') in archive {}".format(
                desc, regex, archive))
      elif len(matches) > 1:
        raise ValueError(
            "Found multiple files for {} (matching regex '{}') in archive {}"
            .format(desc, regex, archive))
      return matches[0]

    tempdir = tempfile.mkdtemp()
    try:
      with zipfile.ZipFile(archive, mode='r') as zip:
        contents = zip.namelist()

        pik_cert_re = r'^pik_certificate.*\.bin$'
        pik_cert = _find_one_match(contents, pik_cert_re,
                                   'intermediate key (PIK) certificate')

        puk_cert_re = r'^puk_certificate.*\.bin$'
        puk_cert = _find_one_match(contents, puk_cert_re,
                                   'unlock key (PUK) certificate')

        puk_re = r'^puk.*\.pem$'
        puk = _find_one_match(contents, puk_re, 'unlock key (PUK)')

        zip.extractall(path=tempdir, members=[pik_cert, puk_cert, puk])

        yield cls(
            intermediate_cert_file=os.path.join(tempdir, pik_cert),
            unlock_cert_file=os.path.join(tempdir, puk_cert),
            unlock_key_file=os.path.join(tempdir, puk))
    finally:
      shutil.rmtree(tempdir)


def MakeAtxUnlockCredential(creds, challenge_file, out_file):
  """Simple reimplementation of 'avbtool make_atx_unlock_credential'.

  Generates an Android Things authenticated unlock credential to authorize
  unlocking AVB on a device.

  This is reimplemented locally for simplicity, which avoids the need to bundle
  this tool with the full avbtool. avbtool also uses openssl by default whereas
  this uses PyCrypto, which makes it easier to support Windows since there are
  no officially supported openssl binary distributions.

  Arguments:
    creds: UnlockCredentials object wrapping the PIK certificate, PUK
      certificate, and PUK private key.
    challenge_file: Challenge obtained via 'oem at-get-vboot-unlock-challenge'.
      This should be the full 52-byte AvbAtxUnlockChallenge struct, not just the
      challenge itself.
    out_file: Output filename to write the AvbAtxUnlockCredential struct to.

  Raises:
    ValueError: If challenge has wrong length.
  """
  # The 16-byte challenge from the bootloader, which needs to be signed with the
  # PUK and included in the AvbAtxUnlockCredential response, is located at the
  # end of the 52-byte AvbAtxUnlockChallenge struct
  CHALLENGE_STRUCT_SIZE = 52
  CHALLENGE_FIELD_SIZE = 16
  with open(challenge_file, 'rb') as f:
    f.seek(0, os.SEEK_END)
    if f.tell() != CHALLENGE_STRUCT_SIZE:
      raise ValueError('Invalid unlock challenge length.')

    f.seek(-CHALLENGE_FIELD_SIZE, os.SEEK_END)
    challenge = f.read()

  hash = SHA512.new(challenge)
  signer = PKCS1_v1_5.new(creds.unlock_key)
  signature = signer.sign(hash)

  with open(out_file, 'wb') as out:
    out.write(struct.pack('<I', 1))  # Format Version
    out.write(creds.intermediate_cert)
    out.write(creds.unlock_cert)
    out.write(signature)


def AuthenticatedUnlock(creds, serial=None, verbose=False):
  """Performs an authenticated AVB unlock of a device over fastboot.

  Arguments:
    creds: UnlockCredentials object wrapping the PIK certificate, PUK
      certificate, and PUK private key.
    serial: [optional] A device serial number or other valid value to be passed
      to fastboot's '-s' switch to select the device to unlock.
    verbose: [optional] Enable verbose output, which prints the fastboot
      commands and their output as the commands are run.
  """

  tempdir = tempfile.mkdtemp()
  try:
    challenge_file = os.path.join(tempdir, 'challenge')
    credential_file = os.path.join(tempdir, 'credential')

    def fastboot_cmd(args):
      args = ['fastboot'] + (['-s', serial] if serial else []) + args
      if verbose:
        print('$ ' + ' '.join(args))

      try:
        out = subprocess.check_output(
            args, stderr=subprocess.STDOUT).decode('utf-8')
      except subprocess.CalledProcessError as e:
        print(e.output.decode('utf-8'))
        print("Command '{}' returned non-zero exit status {}".format(
            ' '.join(e.cmd), e.returncode))
        sys.exit(1)

      if verbose:
        print(out)
      return out

    fastboot_cmd(['oem', 'at-get-vboot-unlock-challenge'])
    fastboot_cmd(['get_staged', challenge_file])
    MakeAtxUnlockCredential(creds, challenge_file, credential_file)
    fastboot_cmd(['stage', credential_file])
    fastboot_cmd(['oem', 'at-unlock-vboot'])

    res = fastboot_cmd(['getvar', 'at-vboot-state'])
    if re.search(r'avb-locked(:\s*|=)0', res) is not None:
      print('Device successfully AVB unlocked')
      return 0
    else:
      print('ERROR: Commands succeeded but device still locked')
      return 1
  finally:
    shutil.rmtree(tempdir)


if __name__ == '__main__':
  parser = argparse.ArgumentParser(
      description=HELP_DESCRIPTION,
      usage=HELP_USAGE,
      epilog=HELP_EPILOG,
      formatter_class=argparse.RawDescriptionHelpFormatter)

  # General optional arguments.
  parser.add_argument(
      '-v',
      '--verbose',
      action='store_true',
      help='verbose; prints fastboot commands and their output')
  parser.add_argument(
      '-s',
      '--serial',
      help=
      "specify device to unlock, either by serial or any other valid value for fastboot's -s arg"
  )

  # User must provide either a unlock credential bundle, or the individual files
  # normally contained in such a bundle.
  # argparse doesn't support specifying this argument format - two groups of
  # mutually exclusive arguments, where one group requires all arguments in that
  # group to be specified - so we define them as optional arguments and do the
  # validation ourselves below.

  # Argument group #1 - Unlock credential zip bundle/archive
  parser.add_argument(
      'bundle',
      metavar='unlock_creds.zip',
      nargs='?',
      help=
      'Unlock using a zip bundle of credentials (e.g. from Developer Console).')

  # Argument group #2 - Individual credential files
  parser.add_argument(
      '--pik_cert',
      metavar='pik_cert.bin',
      help='Path to product intermediate key (PIK) certificate file')
  parser.add_argument(
      '--puk_cert',
      metavar='puk_cert.bin',
      help='Path to product unlock key (PUK) certificate file')
  parser.add_argument(
      '--puk',
      metavar='puk.pem',
      help='Path to product unlock key in PEM format')

  # Print help if no args given
  args = parser.parse_args(args=None if sys.argv[1:] else ['-h'])

  # Do the custom validation described above.
  if args.pik_cert is not None or args.puk_cert is not None or args.puk is not None:
    # Check mutual exclusion with bundle positional argument
    if args.bundle is not None:
      parser.error(
          'bundle argument is mutually exclusive with --pik_cert, --puk_cert, and --puk'
      )

    # Check for 'mutual inclusion' of individual file options
    if args.pik_cert is None:
      parser.error("--pik_cert is required if --puk_cert or --puk' is given")
    if args.puk_cert is None:
      parser.error("--puk_cert is required if --pik_cert or --puk' is given")
    if args.puk is None:
      parser.error("--puk is required if --pik_cert or --puk_cert' is given")
  elif args.bundle is None:
    parser.error(
        'must provide either credentials bundle or individual credential files')

  if args.bundle is not None:
    creds = UnlockCredentials.from_credential_archive(args.bundle)
  else:
    creds = UnlockCredentials.from_files(args.pik_cert, args.puk_cert, args.puk)
  with creds as creds:
    sys.exit(
        AuthenticatedUnlock(creds, serial=args.serial, verbose=args.verbose))
