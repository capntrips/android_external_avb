#!/usr/bin/env python3

# Copyright 2020, The Android Open Source Project
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
"""Command-line tool for AFTL support for Android Verified Boot images."""

import abc
import argparse
import enum
import hashlib
import io
import multiprocessing
import os
import queue
import struct
import subprocess
import sys
import tempfile
import time

# This is to work around temporarily with the issue that python3 does not permit
# relative imports anymore going forward. This adds the proto directory relative
# to the location of aftltool to the sys.path.
# TODO(b/154068467): Implement proper importing of generated *_pb2 modules.
EXEC_PATH = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(EXEC_PATH, 'proto'))

# pylint: disable=wrong-import-position,import-error
import avbtool
import api_pb2
# pylint: enable=wrong-import-position,import-error


class AftlError(Exception):
  """Application-specific errors.

  These errors represent issues for which a stack-trace should not be
  presented.

  Attributes:
    message: Error message.
  """

  def __init__(self, message):
    Exception.__init__(self, message)


def rsa_key_read_pem_bytes(key_path):
  """Reads the bytes out of the passed in PEM file.

  Arguments:
    key_path: A string containing the path to the PEM file.

  Returns:
    A bytearray containing the DER encoded bytes in the PEM file.

  Raises:
    AftlError: If openssl cannot decode the PEM file.
  """
  # Use openssl to decode the PEM file.
  args = ['openssl', 'rsa', '-in', key_path, '-pubout', '-outform', 'DER']
  p = subprocess.Popen(args,
                       stdin=subprocess.PIPE,
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
  (pout, perr) = p.communicate()
  retcode = p.wait()
  if retcode != 0:
    raise AftlError('Error decoding: {}'.format(perr))
  return pout


def check_signature(log_root, log_root_sig,
                    transparency_log_pub_key):
  """Validates the signature provided by the transparency log.

  Arguments:
    log_root: The transparency log_root data structure.
    log_root_sig: The signature of the transparency log_root data structure.
    transparency_log_pub_key: The file path to the transparency log public key.

  Returns:
    True if the signature check passes, otherwise False.
  """

  logsig_tmp = tempfile.NamedTemporaryFile()
  logsig_tmp.write(log_root_sig)
  logsig_tmp.flush()
  logroot_tmp = tempfile.NamedTemporaryFile()
  logroot_tmp.write(log_root)
  logroot_tmp.flush()

  p = subprocess.Popen(['openssl', 'dgst', '-sha256', '-verify',
                        transparency_log_pub_key,
                        '-signature', logsig_tmp.name, logroot_tmp.name],
                       stdin=subprocess.PIPE,
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)

  p.communicate()
  retcode = p.wait()
  if not retcode:
    return True
  return False


# AFTL Merkle Tree Functionality
def rfc6962_hash_leaf(leaf):
  """RFC6962 hashing function for hashing leaves of a Merkle tree.

  Arguments:
    leaf: A bytearray containing the Merkle tree leaf to be hashed.

  Returns:
    A bytearray containing the RFC6962 SHA256 hash of the leaf.
  """
  hasher = hashlib.sha256()
  # RFC6962 states a '0' byte should be prepended to the data.
  # This is done in conjunction with the '1' byte for non-leaf
  # nodes for 2nd preimage attack resistance.
  hasher.update(b'\x00')
  hasher.update(leaf)
  return hasher.digest()


def rfc6962_hash_children(l, r):
  """Calculates the inner Merkle tree node hash of child nodes l and r.

  Arguments:
    l: A bytearray containing the left child node to be hashed.
    r: A bytearray containing the right child node to be hashed.

  Returns:
    A bytearray containing the RFC6962 SHA256 hash of 1|l|r.
  """
  hasher = hashlib.sha256()
  # RFC6962 states a '1' byte should be prepended to the concatenated data.
  # This is done in conjunction with the '0' byte for leaf
  # nodes for 2nd preimage attack resistance.
  hasher.update(b'\x01')
  hasher.update(l)
  hasher.update(r)
  return hasher.digest()


def chain_border_right(seed, proof):
  """Computes a subtree hash along the left-side tree border.

  Arguments:
    seed: A bytearray containing the starting hash.
    proof: A list of bytearrays representing the hashes in the inclusion proof.

  Returns:
    A bytearray containing the left-side subtree hash.
  """
  for h in proof:
    seed = rfc6962_hash_children(h, seed)
  return seed


def chain_inner(seed, proof, leaf_index):
  """Computes a subtree hash on or below the tree's right border.

  Arguments:
    seed: A bytearray containing the starting hash.
    proof: A list of bytearrays representing the hashes in the inclusion proof.
    leaf_index: The current leaf index.

  Returns:
    A bytearray containing the subtree hash.
  """
  for i, h in enumerate(proof):
    if leaf_index >> i & 1 == 0:
      seed = rfc6962_hash_children(seed, h)
    else:
      seed = rfc6962_hash_children(h, seed)
  return seed


def root_from_icp(leaf_index, tree_size, proof, leaf_hash):
  """Calculates the expected Merkle tree root hash.

  Arguments:
    leaf_index: The current leaf index.
    tree_size: The number of nodes in the Merkle tree.
    proof: A list of bytearrays containing the inclusion proof.
    leaf_hash: A bytearray containing the initial leaf hash.

  Returns:
    A bytearray containing the calculated Merkle tree root hash.

  Raises:
    AftlError: If invalid parameters are passed in.
  """
  if leaf_index < 0:
    raise AftlError('Invalid leaf_index value: {}'.format(leaf_index))
  if tree_size < 0:
    raise AftlError('Invalid tree_size value: {}'.format(tree_size))
  if leaf_index >= tree_size:
    err_str = 'leaf_index cannot be equal or larger than tree_size: {}, {}'
    raise AftlError(err_str.format(leaf_index, tree_size))
  if proof is None:
    raise AftlError('Inclusion proof not provided.')
  if leaf_hash is None:
    raise AftlError('No leaf hash provided.')
  # Calculate the point to split the proof into two parts.
  # The split is where the paths to leaves diverge.
  inner = (leaf_index ^ (tree_size - 1)).bit_length()
  result = chain_inner(leaf_hash, proof[:inner], leaf_index)
  result = chain_border_right(result, proof[inner:])
  return result


class AftlImageHeader(object):
  """A class for representing the AFTL image header.

  Attributes:
    magic: Magic for identifying the AftlImage.
    required_icp_version_major: The major version of AVB that wrote the entry.
    required_icp_version_minor: The minor version of AVB that wrote the entry.
    aftl_image_size: Total size of the AftlImage.
    icp_count: Number of inclusion proofs represented in this structure.
  """

  SIZE = 18  # The size of the structure, in bytes
  MAGIC = b'AFTL'
  FORMAT_STRING = ('!4s2L'  # magic, major & minor version.
                   'L'      # AFTL image size.
                   'H')     # number of inclusion proof entries.

  def __init__(self, data=None):
    """Initializes a new AftlImageHeader object.

    Arguments:
      data: If not None, must be a bytearray of size |SIZE|.

    Raises:
      AftlError: If invalid structure for AftlImageHeader.
    """
    assert struct.calcsize(self.FORMAT_STRING) == self.SIZE

    if data:
      (self.magic, self.required_icp_version_major,
       self.required_icp_version_minor, self.aftl_image_size,
       self.icp_count) = struct.unpack(self.FORMAT_STRING, data)
    else:
      self.magic = self.MAGIC
      self.required_icp_version_major = avbtool.AVB_VERSION_MAJOR
      self.required_icp_version_minor = avbtool.AVB_VERSION_MINOR
      self.aftl_image_size = self.SIZE
      self.icp_count = 0
    if not self.is_valid():
      raise AftlError('Invalid structure for AftlImageHeader.')

  def encode(self):
    """Serializes the AftlImageHeader |SIZE| to bytes.

    Returns:
      The encoded AftlImageHeader as bytes.

    Raises:
      AftlError: If invalid structure for AftlImageHeader.
    """
    if not self.is_valid():
      raise AftlError('Invalid structure for AftlImageHeader')
    return struct.pack(self.FORMAT_STRING, self.magic,
                       self.required_icp_version_major,
                       self.required_icp_version_minor,
                       self.aftl_image_size,
                       self.icp_count)

  def is_valid(self):
    """Ensures that values in the AftlImageHeader are sane.

    Returns:
      True if the values in the AftlImageHeader are sane, False otherwise.
    """
    if self.magic != AftlImageHeader.MAGIC:
      sys.stderr.write(
          'AftlImageHeader: magic value mismatch: {}\n'
          .format(repr(self.magic)))
      return False

    if self.required_icp_version_major > avbtool.AVB_VERSION_MAJOR:
      sys.stderr.write('AftlImageHeader: major version mismatch: {}\n'.format(
          self.required_icp_version_major))
      return False

    if self.required_icp_version_minor > avbtool.AVB_VERSION_MINOR:
      sys.stderr.write('AftlImageHeader: minor version mismatch: {}\n'.format(
          self.required_icp_version_minor))
      return False

    if self.aftl_image_size < self.SIZE:
      sys.stderr.write('AftlImageHeader: Invalid AFTL image size: {}\n'.format(
          self.aftl_image_size))
      return False

    if self.icp_count < 0 or self.icp_count > 65535:
      sys.stderr.write(
          'AftlImageHeader: ICP entry count out of range: {}\n'.format(
              self.icp_count))
      return False
    return True

  def print_desc(self, o):
    """Print the AftlImageHeader.

    Arguments:
      o: The object to write the output to.
    """
    o.write('  AFTL image header:\n')
    i = ' ' * 4
    fmt = '{}{:25}{}\n'
    o.write(fmt.format(i, 'Major version:', self.required_icp_version_major))
    o.write(fmt.format(i, 'Minor version:', self.required_icp_version_minor))
    o.write(fmt.format(i, 'Image size:', self.aftl_image_size))
    o.write(fmt.format(i, 'ICP entries count:', self.icp_count))


class AftlIcpEntry(object):
  """A class for the transparency log inclusion proof entries.

  The data that represents each of the components of the ICP entry are stored
  immediately following the ICP entry header. The format is log_url,
  SignedLogRoot, and inclusion proof hashes.

  Attributes:
    log_url_size: Length of the string representing the transparency log URL.
    leaf_index: Leaf index in the transparency log representing this entry.
    log_root_descriptor_size: Size of the transparency log's SignedLogRoot.
    annotation_leaf_size: Size of the SignedVBMetaPrimaryAnnotationLeaf passed
        to the log.
    log_root_sig_size: Size in bytes of the log_root_signature
    proof_hash_count: Number of hashes comprising the inclusion proof.
    inc_proof_size: The total size of the inclusion proof, in bytes.
    log_url: The URL for the transparency log that generated this inclusion
        proof.
    log_root_descriptor: The data comprising the signed tree head structure.
    annotation_leaf: The data comprising the SignedVBMetaPrimaryAnnotationLeaf
        leaf.
    log_root_signature: The data comprising the log root signature.
    proofs: The hashes comprising the inclusion proof.

  """
  SIZE = 27  # The size of the structure, in bytes
  FORMAT_STRING = ('!L'   # transparency log server url size
                   'Q'    # leaf index
                   'L'    # log root descriptor size
                   'L'    # firmware info leaf size
                   'H'    # log root signature size
                   'B'    # number of hashes in the inclusion proof
                   'L')   # size of the inclusion proof in bytes
  # This header is followed by the log_url, log_root_descriptor,
  # annotation leaf, log root signature, and the proofs elements.

  def __init__(self, data=None):
    """Initializes a new ICP entry object.

    Arguments:
      data: If not None, must be a bytearray of size >= |SIZE|.

    Raises:
      AftlError: If data does not represent a well-formed AftlIcpEntry.
    """
    # Assert the header structure is of a sane size.
    assert struct.calcsize(self.FORMAT_STRING) == self.SIZE

    if data:
      # Deserialize the header from the data.
      (self._log_url_size_expected,
       self.leaf_index,
       self._log_root_descriptor_size_expected,
       self._annotation_leaf_size_expected,
       self._log_root_sig_size_expected,
       self._proof_hash_count_expected,
       self._inc_proof_size_expected) = struct.unpack(self.FORMAT_STRING,
                                                      data[0:self.SIZE])

      # Deserialize ICP entry components from the data.
      expected_format_string = '{}s{}s{}s{}s{}s'.format(
          self._log_url_size_expected,
          self._log_root_descriptor_size_expected,
          self._annotation_leaf_size_expected,
          self._log_root_sig_size_expected,
          self._inc_proof_size_expected)

      (log_url, log_root_descriptor_bytes, annotation_leaf_bytes,
       self.log_root_signature, proof_bytes) = struct.unpack(
           expected_format_string, data[self.SIZE:self.get_expected_size()])

      self.log_url = log_url.decode('ascii')
      self.log_root_descriptor = TrillianLogRootDescriptor(
          log_root_descriptor_bytes)

      self.annotation_leaf = SignedVBMetaPrimaryAnnotationLeaf.parse(
          annotation_leaf_bytes)

      self.proofs = []
      if self._proof_hash_count_expected > 0:
        proof_idx = 0
        hash_size = (self._inc_proof_size_expected
                     // self._proof_hash_count_expected)
        for _ in range(self._proof_hash_count_expected):
          proof = proof_bytes[proof_idx:(proof_idx+hash_size)]
          self.proofs.append(proof)
          proof_idx += hash_size
    else:
      self.leaf_index = 0
      self.log_url = ''
      self.log_root_descriptor = TrillianLogRootDescriptor()
      self.annotation_leaf = SignedVBMetaPrimaryAnnotationLeaf()
      self.log_root_signature = b''
      self.proofs = []
    if not self.is_valid():
      raise AftlError('Invalid structure for AftlIcpEntry')

  @property
  def log_url_size(self):
    """Gets the size of the log_url attribute."""
    if hasattr(self, 'log_url'):
      return len(self.log_url)
    return self._log_url_size_expected

  @property
  def log_root_descriptor_size(self):
    """Gets the size of the log_root_descriptor attribute."""
    if hasattr(self, 'log_root_descriptor'):
      return self.log_root_descriptor.get_expected_size()
    return self._log_root_descriptor_size_expected

  @property
  def annotation_leaf_size(self):
    """Gets the size of the annotation_leaf attribute."""
    if hasattr(self, 'annotation_leaf'):
      return self.annotation_leaf.get_expected_size()
    return self._annotation_leaf_size_expected

  @property
  def log_root_sig_size(self):
    """Gets the size of the log_root signature."""
    if hasattr(self, 'log_root_signature'):
      return len(self.log_root_signature)
    return self._log_root_sig_size_expected

  @property
  def proof_hash_count(self):
    """Gets the number of proof hashes."""
    if hasattr(self, 'proofs'):
      return len(self.proofs)
    return self._proof_hash_count_expected

  @property
  def inc_proof_size(self):
    """Gets the total size of the proof hashes in bytes."""
    if hasattr(self, 'proofs'):
      result = 0
      for proof in self.proofs:
        result += len(proof)
      return result
    return self._inc_proof_size_expected

  def verify_icp(self, transparency_log_pub_key):
    """Verifies the contained inclusion proof given the public log key.

    Arguments:
      transparency_log_pub_key: The path to the trusted public key for the log.

    Returns:
      True if the calculated signature matches AftlIcpEntry's. False otherwise.
    """
    if not transparency_log_pub_key:
      return False

    leaf_hash = rfc6962_hash_leaf(self.annotation_leaf.encode())
    calc_root = root_from_icp(self.leaf_index,
                              self.log_root_descriptor.tree_size,
                              self.proofs,
                              leaf_hash)
    if ((calc_root == self.log_root_descriptor.root_hash) and
        check_signature(
            self.log_root_descriptor.encode(),
            self.log_root_signature,
            transparency_log_pub_key)):
      return True
    return False

  def verify_vbmeta_image(self, vbmeta_image, transparency_log_pub_key):
    """Verify the inclusion proof for the given VBMeta image.

    Arguments:
      vbmeta_image: A bytearray with the VBMeta image.
      transparency_log_pub_key: File path to the PEM file containing the trusted
        transparency log public key.

    Returns:
      True if the inclusion proof validates and the vbmeta hash of the given
      VBMeta image matches the one in the annotation leaf; otherwise False.
    """
    if not vbmeta_image:
      return False

    # Calculate the hash of the vbmeta image.
    vbmeta_hash = hashlib.sha256(vbmeta_image).digest()

    # Validates the inclusion proof and then compare the calculated vbmeta_hash
    # against the one in the inclusion proof.
    return (self.verify_icp(transparency_log_pub_key)
            and self.annotation_leaf.annotation.vbmeta_hash == vbmeta_hash)

  def encode(self):
    """Serializes the header |SIZE| and data to bytes.

    Returns:
      bytes with the encoded header.

    Raises:
      AftlError: If invalid entry structure.
    """
    proof_bytes = bytearray()
    if not self.is_valid():
      raise AftlError('Invalid AftlIcpEntry structure')

    expected_format_string = '{}{}s{}s{}s{}s{}s'.format(
        self.FORMAT_STRING,
        self.log_url_size,
        self.log_root_descriptor_size,
        self.annotation_leaf_size,
        self.log_root_sig_size,
        self.inc_proof_size)

    for proof in self.proofs:
      proof_bytes.extend(proof)

    return struct.pack(expected_format_string,
                       self.log_url_size, self.leaf_index,
                       self.log_root_descriptor_size, self.annotation_leaf_size,
                       self.log_root_sig_size, self.proof_hash_count,
                       self.inc_proof_size, self.log_url.encode('ascii'),
                       self.log_root_descriptor.encode(),
                       self.annotation_leaf.encode(),
                       self.log_root_signature,
                       proof_bytes)

  def translate_response(self, log_url, avbm_response):
    """Translates an AddVBMetaResponse object to an AftlIcpEntry.

    Arguments:
      log_url: String representing the transparency log URL.
      avbm_response: The AddVBMetaResponse object to translate.
    """
    self.log_url = log_url

    # Deserializes from AddVBMetaResponse.
    proof = avbm_response.annotation_proof
    self.leaf_index = proof.proof.leaf_index
    self.log_root_descriptor = TrillianLogRootDescriptor(proof.sth.log_root)
    self.annotation_leaf = SignedVBMetaPrimaryAnnotationLeaf.parse(
        avbm_response.annotation_leaf)
    self.log_root_signature = proof.sth.log_root_signature
    self.proofs = proof.proof.hashes

  def get_expected_size(self):
    """Gets the expected size of the full entry out of the header.

    Returns:
      The expected size of the AftlIcpEntry from the header.
    """
    return (self.SIZE + self.log_url_size + self.log_root_descriptor_size +
            self.annotation_leaf_size + self.log_root_sig_size +
            self.inc_proof_size)

  def is_valid(self):
    """Ensures that values in an AftlIcpEntry structure are sane.

    Returns:
      True if the values in the AftlIcpEntry are sane, False otherwise.
    """
    if self.leaf_index < 0:
      sys.stderr.write('ICP entry: leaf index out of range: '
                       '{}.\n'.format(self.leaf_index))
      return False

    if (not self.log_root_descriptor or
        not isinstance(self.log_root_descriptor, TrillianLogRootDescriptor) or
        not self.log_root_descriptor.is_valid()):
      sys.stderr.write('ICP entry: invalid TrillianLogRootDescriptor.\n')
      return False

    if (not self.annotation_leaf or
        not isinstance(self.annotation_leaf, Leaf)):
      sys.stderr.write('ICP entry: invalid Leaf.\n')
      return False
    return True

  def print_desc(self, o):
    """Print the ICP entry.

    Arguments:
      o: The object to write the output to.
    """
    i = ' ' * 4
    fmt = '{}{:25}{}\n'
    o.write(fmt.format(i, 'Transparency Log:', self.log_url))
    o.write(fmt.format(i, 'Leaf index:', self.leaf_index))
    o.write('    ICP hashes:              ')
    for i, proof_hash in enumerate(self.proofs):
      if i != 0:
        o.write(' ' * 29)
      o.write('{}\n'.format(proof_hash.hex()))
    self.log_root_descriptor.print_desc(o)
    self.annotation_leaf.print_desc(o)


class TrillianLogRootDescriptor(object):
  """A class representing the Trillian log_root descriptor.

  Taken from Trillian definitions:
  https://github.com/google/trillian/blob/master/trillian.proto#L255

  Attributes:
    version: The version number of the descriptor. Currently only version=1 is
        supported.
    tree_size: The size of the tree.
    root_hash_size: The size of the root hash in bytes. Valid values are between
        0 and 128.
    root_hash: The root hash as bytearray().
    timestamp: The timestamp in nanoseconds.
    revision: The revision number as long.
    metadata_size: The size of the metadata in bytes. Valid values are between
        0 and 65535.
    metadata: The metadata as bytearray().
  """
  FORMAT_STRING_PART_1 = ('!H'  # version
                          'Q'   # tree_size
                          'B'   # root_hash_size
                         )

  FORMAT_STRING_PART_2 = ('!Q'  # timestamp
                          'Q'   # revision
                          'H'   # metadata_size
                         )

  def __init__(self, data=None):
    """Initializes a new TrillianLogRoot descriptor."""
    if data:
      # Parses first part of the log_root descriptor.
      data_length = struct.calcsize(self.FORMAT_STRING_PART_1)
      (self.version, self.tree_size, self.root_hash_size) = struct.unpack(
          self.FORMAT_STRING_PART_1, data[0:data_length])
      data = data[data_length:]

      # Parses the root_hash bytes if the size indicates existance.
      if self.root_hash_size > 0:
        self.root_hash = data[0:self.root_hash_size]
        data = data[self.root_hash_size:]
      else:
        self.root_hash = b''

      # Parses second part of the log_root descriptor.
      data_length = struct.calcsize(self.FORMAT_STRING_PART_2)
      (self.timestamp, self.revision, self.metadata_size) = struct.unpack(
          self.FORMAT_STRING_PART_2, data[0:data_length])
      data = data[data_length:]

      # Parses the metadata if the size indicates existance.
      if self.metadata_size > 0:
        self.metadata = data[0:self.metadata_size]
      else:
        self.metadata = b''
    else:
      self.version = 1
      self.tree_size = 0
      self.root_hash_size = 0
      self.root_hash = b''
      self.timestamp = 0
      self.revision = 0
      self.metadata_size = 0
      self.metadata = b''

    if not self.is_valid():
      raise AftlError('Invalid structure for TrillianLogRootDescriptor.')

  def get_expected_size(self):
    """Calculates the expected size of the TrillianLogRootDescriptor.

    Returns:
      The expected size of the TrillianLogRootDescriptor.
    """
    return (struct.calcsize(self.FORMAT_STRING_PART_1) + self.root_hash_size +
            struct.calcsize(self.FORMAT_STRING_PART_2) + self.metadata_size)

  def encode(self):
    """Serializes the TrillianLogDescriptor to a bytearray().

    Returns:
      A bytearray() with the encoded header.

    Raises:
      AftlError: If invalid entry structure.
    """
    if not self.is_valid():
      raise AftlError('Invalid structure for TrillianLogRootDescriptor.')

    expected_format_string = '{}{}s{}{}s'.format(
        self.FORMAT_STRING_PART_1,
        self.root_hash_size,
        self.FORMAT_STRING_PART_2[1:],
        self.metadata_size)

    return struct.pack(expected_format_string,
                       self.version, self.tree_size, self.root_hash_size,
                       self.root_hash, self.timestamp, self.revision,
                       self.metadata_size, self.metadata)

  def is_valid(self):
    """Ensures that values in the descritor are sane.

    Returns:
      True if the values are sane; otherwise False.
    """
    cls = self.__class__.__name__
    if self.version != 1:
      sys.stderr.write('{}: Bad version value {}.\n'.format(cls, self.version))
      return False
    if self.tree_size < 0:
      sys.stderr.write('{}: Bad tree_size value {}.\n'.format(cls,
                                                              self.tree_size))
      return False
    if self.root_hash_size < 0 or self.root_hash_size > 128:
      sys.stderr.write('{}: Bad root_hash_size value {}.\n'.format(
          cls, self.root_hash_size))
      return False
    if len(self.root_hash) != self.root_hash_size:
      sys.stderr.write('{}: root_hash_size {} does not match with length of '
                       'root_hash {}.\n'.format(cls, self.root_hash_size,
                                                len(self.root_hash)))
      return False
    if self.timestamp < 0:
      sys.stderr.write('{}: Bad timestamp value {}.\n'.format(cls,
                                                              self.timestamp))
      return False
    if self.revision < 0:
      sys.stderr.write('{}: Bad revision value {}.\n'.format(cls,
                                                             self.revision))
      return False
    if self.metadata_size < 0 or self.metadata_size > 65535:
      sys.stderr.write('{}: Bad metadatasize value {}.\n'.format(
          cls, self.metadata_size))
      return False
    if len(self.metadata) != self.metadata_size:
      sys.stderr.write('{}: metadata_size {} does not match with length of'
                       'metadata {}.\n'.format(cls, self.metadata_size,
                                               len(self.metadata)))
      return False
    return True

  def print_desc(self, o):
    """Print the TrillianLogRootDescriptor.

    Arguments:
      o: The object to write the output to.
    """
    o.write('    Log Root Descriptor:\n')
    i = ' ' * 6
    fmt = '{}{:23}{}\n'
    o.write(fmt.format(i, 'Version:', self.version))
    o.write(fmt.format(i, 'Tree size:', self.tree_size))
    o.write(fmt.format(i, 'Root hash size:', self.root_hash_size))
    if self.root_hash_size > 0:
      o.write(fmt.format(i, 'Root hash:', self.root_hash.hex()))
      o.write(fmt.format(i, 'Timestamp (ns):', self.timestamp))
    o.write(fmt.format(i, 'Revision:', self.revision))
    o.write(fmt.format(i, 'Metadata size:', self.metadata_size))
    if self.metadata_size > 0:
      o.write(fmt.format(i, 'Metadata:', self.metadata.hex()))


def tls_decode_bytes(byte_size, stream):
  """Decodes a variable-length vector.

  In the TLS presentation language, a variable-length vector is a pair
  (size, value). |size| describes the size of the |value| to read
  in bytes. All values are encoded in big-endian.
  See https://tools.ietf.org/html/rfc8446#section-3 for more details.

  Arguments:
      byte_size: A format character as described in the struct module
          which describes the expected length of the size. For
          instance, "B", "H", "L" or "Q".
      stream: a BytesIO which contains the value to decode.

  Returns:
    A bytes containing the value decoded.

  Raises:
    AftlError: If |byte_size| is not a known format character, or if not
    enough data is available to decode the size or the value.
  """
  byte_size_format = "!" + byte_size
  try:
    byte_size_length = struct.calcsize(byte_size_format)
  except struct.error:
    raise AftlError("Invalid byte_size character: {}. It must be a "
                    "format supported by struct.".format(byte_size))
  try:
    value_size = struct.unpack(byte_size_format,
                               stream.read(byte_size_length))[0]
  except struct.error:
    raise AftlError("Not enough data to read size: {}".format(byte_size))
  value = stream.read(value_size)
  if value_size != len(value):
    raise AftlError("Not enough data to read value: "
                    "{} != {}".format(value_size, len(value)))
  return value

def tls_encode_bytes(byte_size, value, stream):
  """Encodes a variable-length vector.

  In the TLS presentation language, a variable-length vector is a pair
  (size, value). |size| describes the size of the |value| to read
  in bytes. All values are encoded in big-endian.
  See https://tools.ietf.org/html/rfc8446#section-3 for more details.

  Arguments:
      byte_size: A format character as described in the struct module
          which describes the expected length of the size. For
          instance, "B", "H", "L" or "Q".
      value: the value to encode. The length of |value| must be
          representable with |byte_size|.
      stream: a BytesIO to which the value is encoded to.

  Raises:
    AftlError: If |byte_size| is not a known format character, or if
    |value|'s length cannot be represent with |byte_size|.
  """
  byte_size_format = "!" + byte_size
  try:
    stream.write(struct.pack(byte_size_format, len(value)))
  except struct.error:
    # Whether byte_size is invalid or not large enough to represent value,
    # struct returns an struct.error exception. Instead of matching on the
    # exception message, capture both cases in a generic message.
    raise AftlError("Invalid byte_size to store {} bytes".format(len(value)))
  stream.write(value)

class HashAlgorithm(enum.Enum):
  SHA256 = 0

class SignatureAlgorithm(enum.Enum):
  RSA = 0
  ECDSA = 1

class Signature(object):
  """Represents a signature of some data.

  It is usually made using a manufacturer key and used to sign part of a leaf
  that belongs to the transparency log. The encoding of this structure must
  match the server expectation.

  Attributes:
    hash_algorithm: the HashAlgorithm used for the signature.
    signature_algorithm: the SignatureAlgorithm used.
    signature: the raw signature in bytes.
  """
  FORMAT_STRING = ('!B'    # Hash algorithm
                   'B'     # Signing algorithm
                  )
  # Followed by the raw signature, encoded as a TLS variable-length vector
  # which size is represented using 2 bytes.

  def __init__(self, hash_algorithm=HashAlgorithm.SHA256,
               signature_algorithm=SignatureAlgorithm.RSA, signature=b''):
    self.hash_algorithm = hash_algorithm
    self.signature_algorithm = signature_algorithm
    self.signature = signature

  @classmethod
  def parse(cls, stream):
    """Parses a TLS-encoded structure and returns a new Signature.

    Arguments:
      stream: a BytesIO to read the signature from.

    Returns:
      A new Signature object.

    Raises:
      AftlError: If the hash algorithm or signature algorithm value is
        unknown; or if the decoding failed.
    """
    data_length = struct.calcsize(cls.FORMAT_STRING)
    (hash_algorithm, signature_algorithm) = struct.unpack(
        cls.FORMAT_STRING, stream.read(data_length))
    try:
      hash_algorithm = HashAlgorithm(hash_algorithm)
    except ValueError:
      raise AftlError('unknown hash algorithm: {}'.format(hash_algorithm))
    try:
      signature_algorithm = SignatureAlgorithm(signature_algorithm)
    except ValueError:
      raise AftlError('unknown signature algorithm: {}'.format(
          signature_algorithm))
    signature = tls_decode_bytes('H', stream)
    return Signature(hash_algorithm, signature_algorithm, signature)

  def get_expected_size(self):
    """Returns the size of the encoded Signature."""
    return struct.calcsize(self.FORMAT_STRING) + \
        struct.calcsize('H') + len(self.signature)

  def encode(self, stream):
    """Encodes the Signature.

    Arguments:
      stream: a BytesIO to which the signature is written.
    """
    stream.write(struct.pack(self.FORMAT_STRING, self.hash_algorithm.value,
                             self.signature_algorithm.value))
    tls_encode_bytes('H', self.signature, stream)

class VBMetaPrimaryAnnotation(object):
  """An annotation that contains metadata about a VBMeta image.

  Attributes:
    vbmeta_hash: the SHA256 of the VBMeta it references.
    version_incremental: the version incremental of the build, as string.
    manufacturer_key_hash: the hash of the manufacturer key that will
        sign this annotation.
    description: a free-form field.
  """

  def __init__(self, vbmeta_hash=b'', version_incremental='',
               manufacturer_key_hash=b'', description=''):
    """Default constructor."""
    self.vbmeta_hash = vbmeta_hash
    self.version_incremental = version_incremental
    self.manufacturer_key_hash = manufacturer_key_hash
    self.description = description

  @classmethod
  def parse(cls, stream):
    """Parses a VBMetaPrimaryAnnotation from data.

    Arguments:
      stream: an io.BytesIO to decode the annotation from.

    Returns:
      A new VBMetaPrimaryAnnotation.

    Raises:
      AftlError: If an error occured while parsing the annotation.
    """
    vbmeta_hash = tls_decode_bytes("B", stream)
    version_incremental = tls_decode_bytes("B", stream)
    try:
      version_incremental = version_incremental.decode("ascii")
    except UnicodeError:
      raise AftlError('Failed to convert version incremental to an ASCII'
                      'string')
    manufacturer_key_hash = tls_decode_bytes("B", stream)
    description = tls_decode_bytes("H", stream)
    try:
      description = description.decode("utf-8")
    except UnicodeError:
      raise AftlError('Failed to convert description to an UTF-8 string')
    return cls(vbmeta_hash, version_incremental, manufacturer_key_hash,
               description)

  def sign(self, manufacturer_key_path, signing_helper=None,
           signing_helper_with_files=None):
    """Signs the annotation.

    Arguments:
      manufacturer_key_path: Path to key used to sign messages sent to the
        transparency log servers.
      signing_helper: Program which signs a hash and returns a signature.
      signing_helper_with_files: Same as signing_helper but uses files instead.

    Returns:
      A new SignedVBMetaPrimaryAnnotation.

    Raises:
      AftlError: If an error occured while signing the annotation.
    """
    # AFTL supports SHA256_RSA4096 for now, more will be available.
    algorithm_name = 'SHA256_RSA4096'
    encoded_leaf = io.BytesIO()
    self.encode(encoded_leaf)
    try:
      rsa_key = avbtool.RSAPublicKey(manufacturer_key_path)
      raw_signature = rsa_key.sign(algorithm_name, encoded_leaf.getvalue(),
                                   signing_helper, signing_helper_with_files)
    except avbtool.AvbError as e:
      raise AftlError('Failed to sign VBMetaPrimaryAnnotation with '
                      '--manufacturer_key: {}'.format(e))
    signature = Signature(hash_algorithm=HashAlgorithm.SHA256,
                          signature_algorithm=SignatureAlgorithm.RSA,
                          signature=raw_signature)
    return SignedVBMetaPrimaryAnnotation(signature=signature, annotation=self)

  def encode(self, stream):
    """Encodes the VBMetaPrimaryAnnotation.

    Arguments:
      stream: a BytesIO to which the signature is written.

    Raises:
      AftlError: If the encoding failed.
    """
    tls_encode_bytes("B", self.vbmeta_hash, stream)
    try:
      tls_encode_bytes("B", self.version_incremental.encode("ascii"), stream)
    except UnicodeError:
      raise AftlError('Unable to encode version incremental to ASCII')
    tls_encode_bytes("B", self.manufacturer_key_hash, stream)
    try:
      tls_encode_bytes("H", self.description.encode("utf-8"), stream)
    except UnicodeError:
      raise AftlError('Unable to encode description to UTF-8')

  def get_expected_size(self):
    """Returns the size of the encoded annotation."""
    b = io.BytesIO()
    self.encode(b)
    return len(b.getvalue())

  def print_desc(self, o):
    """Print the VBMetaPrimaryAnnotation.

    Arguments:
      o: The object to write the output to.
    """
    o.write('      VBMeta Primary Annotation:\n')
    i = ' ' * 8
    fmt = '{}{:23}{}\n'
    if self.vbmeta_hash:
      o.write(fmt.format(i, 'VBMeta hash:', self.vbmeta_hash.hex()))
    if self.version_incremental:
      o.write(fmt.format(i, 'Version incremental:', self.version_incremental))
    if self.manufacturer_key_hash:
      o.write(fmt.format(i, 'Manufacturer key hash:',
                         self.manufacturer_key_hash.hex()))
    if self.description:
      o.write(fmt.format(i, 'Description:', self.description))


class SignedVBMetaPrimaryAnnotation(object):
  """A Signed VBMetaPrimaryAnnotation.

  Attributes:
    signature: a Signature.
    annotation: a VBMetaPrimaryAnnotation.
  """

  def __init__(self, signature=None, annotation=None):
    """Default constructor."""
    if not signature:
      signature = Signature()
    self.signature = signature
    if not annotation:
      annotation = VBMetaPrimaryAnnotation()
    self.annotation = annotation

  @classmethod
  def parse(cls, stream):
    """Parses a signed annotation."""
    signature = Signature.parse(stream)
    annotation = VBMetaPrimaryAnnotation.parse(stream)
    return cls(signature, annotation)

  def get_expected_size(self):
    """Returns the size of the encoded signed annotation."""
    return self.signature.get_expected_size() + \
             self.annotation.get_expected_size()

  def encode(self, stream):
    """Encodes the SignedVBMetaPrimaryAnnotation.

    Arguments:
      stream: a BytesIO to which the object is written.

    Raises:
      AftlError: If the encoding failed.
    """
    self.signature.encode(stream)
    self.annotation.encode(stream)

  def print_desc(self, o):
    """Prints the annotation.

    Arguments:
      o: The object to write the output to.
    """
    self.annotation.print_desc(o)

class Leaf(abc.ABC):
  """An abstract class to represent the leaves in the transparency log."""
  FORMAT_STRING = ('!B'   # Version
                   'Q'    # Timestamp
                   'B'    # LeafType
                  )

  class LeafType(enum.Enum):
    VBMetaType = 0
    SignedVBMetaPrimaryAnnotationType = 1

  def __init__(self, version=1, timestamp=0, leaf_type=LeafType.VBMetaType):
    """Build a new leaf."""
    self.version = version
    self.timestamp = timestamp
    self.leaf_type = leaf_type

  @classmethod
  def _parse_header(cls, stream):
    """Parses the header of a leaf.

    This is called with the parse method of the subclasses.

    Arguments:
      stream: a BytesIO to read the header from.

    Returns:
      A tuple (version, timestamp, leaf_type).

    Raises:
      AftlError: If the header cannot be decoded; or if the leaf type is
          unknown.
    """
    data_length = struct.calcsize(cls.FORMAT_STRING)
    try:
      (version, timestamp, leaf_type) = struct.unpack(
          cls.FORMAT_STRING, stream.read(data_length))
    except struct.error:
      raise AftlError("Not enough data to parse leaf header")
    try:
      leaf_type = cls.LeafType(leaf_type)
    except ValueError:
      raise AftlError("Unknown leaf type: {}".format(leaf_type))
    return version, timestamp, leaf_type

  @classmethod
  @abc.abstractmethod
  def parse(cls, data):
    """Parses a leaf and returned a new object.

    This abstract method must be implemented by the subclass. It may use
    _parse_header to parse the common fields.

    Arguments:
      data: a bytes-like object.

    Returns:
      An object of the type of the particular subclass.

    Raises:
      AftlError: If the leaf type is incorrect; or if the decoding failed.
    """

  @abc.abstractmethod
  def encode(self):
    """Encodes a leaf.

    This abstract method must be implemented by the subclass. It may use
    _encode_header to encode the common fields.

    Returns:
      A bytes with the encoded leaf.

    Raises:
      AftlError: If the encoding failed.
    """

  def _get_expected_header_size(self):
    """Returns the size of the leaf header."""
    return struct.calcsize(self.FORMAT_STRING)

  def _encode_header(self, stream):
    """Encodes the header of the leaf.

    This method is called by the encode method in the subclass.

    Arguments:
      stream: a BytesIO to which the object is written.

    Raises:
      AftlError: If the encoding failed.
    """
    try:
      stream.write(struct.pack(self.FORMAT_STRING, self.version, self.timestamp,
                               self.leaf_type.value))
    except struct.error:
      raise AftlError('Unable to encode the leaf header')

  def print_desc(self, o):
    """Prints the leaf header.

    Arguments:
      o: The object to write the output to.
    """
    i = ' ' * 6
    fmt = '{}{:23}{}\n'
    o.write(fmt.format(i, 'Version:', self.version))
    o.write(fmt.format(i, 'Timestamp:', self.timestamp))
    o.write(fmt.format(i, 'Type:', self.leaf_type))


class SignedVBMetaPrimaryAnnotationLeaf(Leaf):
  """A Signed VBMetaPrimaryAnnotation leaf."""

  def __init__(self, version=1, timestamp=0,
               signed_vbmeta_primary_annotation=None):
    """Builds a new Signed VBMeta Primary Annotation leaf."""
    super(SignedVBMetaPrimaryAnnotationLeaf, self).__init__(
        version=version, timestamp=timestamp,
        leaf_type=self.LeafType.SignedVBMetaPrimaryAnnotationType)
    if not signed_vbmeta_primary_annotation:
      signed_vbmeta_primary_annotation = SignedVBMetaPrimaryAnnotation()
    self.signed_vbmeta_primary_annotation = signed_vbmeta_primary_annotation

  @property
  def annotation(self):
    """Returns the VBMetaPrimaryAnnotation contained in the leaf."""
    return self.signed_vbmeta_primary_annotation.annotation

  @property
  def signature(self):
    """Returns the Signature contained in the leaf."""
    return self.signed_vbmeta_primary_annotation.signature

  @classmethod
  def parse(cls, data):
    """Parses an encoded contained in data.

    Arguments:
      data: a bytes-like object.

    Returns:
      A SignedVBMetaPrimaryAnnotationLeaf.

    Raises:
      AftlError if the leaf type is incorrect; or if the decoding failed.
    """
    encoded_leaf = io.BytesIO(data)
    version, timestamp, leaf_type = Leaf._parse_header(encoded_leaf)
    if leaf_type != Leaf.LeafType.SignedVBMetaPrimaryAnnotationType:
      raise AftlError("Incorrect leaf type")
    signed_annotation = SignedVBMetaPrimaryAnnotation.parse(encoded_leaf)
    return cls(version=version, timestamp=timestamp,
               signed_vbmeta_primary_annotation=signed_annotation)

  def get_expected_size(self):
    """Returns the size of the leaf."""
    size = self._get_expected_header_size()
    if self.signed_vbmeta_primary_annotation:
      size += self.signed_vbmeta_primary_annotation.get_expected_size()
    return size

  def encode(self):
    """Encodes the leaf.

    Returns:
      bytes which contains the encoded leaf.

    Raises:
      AftlError: If the encoding failed.
    """
    stream = io.BytesIO()
    self._encode_header(stream)
    self.signed_vbmeta_primary_annotation.encode(stream)
    return stream.getvalue()

  def print_desc(self, o):
    """Prints the leaf.

    Arguments:
      o: The object to write the output to.
    """
    i = ' ' * 4
    fmt = '{}{:25}{}\n'
    o.write(fmt.format(i, 'Leaf:', ''))
    super(SignedVBMetaPrimaryAnnotationLeaf, self).print_desc(o)
    self.signed_vbmeta_primary_annotation.print_desc(o)


class AftlImage(object):
  """A class for the AFTL image, which contains the transparency log ICPs.

  This encapsulates an AFTL ICP section with all information required to
  validate an inclusion proof.

  Attributes:
    image_header: A header for the section.
    icp_entries: A list of AftlIcpEntry objects representing the inclusion
        proofs.
  """

  def __init__(self, data=None):
    """Initializes a new AftlImage section.

    Arguments:
      data: If not None, must be a bytearray representing an AftlImage.

    Raises:
      AftlError: If the data does not represent a well-formed AftlImage.
    """
    if data:
      image_header_bytes = data[0:AftlImageHeader.SIZE]
      self.image_header = AftlImageHeader(image_header_bytes)
      if not self.image_header.is_valid():
        raise AftlError('Invalid AftlImageHeader.')
      icp_count = self.image_header.icp_count

      # Jump past the header for entry deserialization.
      icp_index = AftlImageHeader.SIZE
      # Validate each entry.
      self.icp_entries = []
      # add_icp_entry() updates entries and header, so set header count to
      # compensate.
      self.image_header.icp_count = 0
      for i in range(icp_count):
        # Get the entry header from the AftlImage.
        cur_icp_entry = AftlIcpEntry(data[icp_index:])
        cur_icp_entry_size = cur_icp_entry.get_expected_size()
        # Now validate the entry structure.
        if not cur_icp_entry.is_valid():
          raise AftlError('Validation of ICP entry {} failed.'.format(i))
        self.add_icp_entry(cur_icp_entry)
        icp_index += cur_icp_entry_size
    else:
      self.image_header = AftlImageHeader()
      self.icp_entries = []
    if not self.is_valid():
      raise AftlError('Invalid AftlImage.')

  def add_icp_entry(self, icp_entry):
    """Adds a new AftlIcpEntry to the AftlImage, updating fields as needed.

    Arguments:
      icp_entry: An AftlIcpEntry structure.
    """
    self.icp_entries.append(icp_entry)
    self.image_header.icp_count += 1
    self.image_header.aftl_image_size += icp_entry.get_expected_size()

  def verify_vbmeta_image(self, vbmeta_image, transparency_log_pub_keys):
    """Verifies the contained inclusion proof given the public log key.

    Arguments:
      vbmeta_image: The vbmeta_image that should be verified against the
        inclusion proof.
      transparency_log_pub_keys: List of paths to PEM files containing trusted
        public keys that correspond with the transparency_logs.

    Returns:
      True if all the inclusion proofs in the AfltDescriptor validate, are
      signed by one of the give transparency log public keys; otherwise false.
    """
    if not transparency_log_pub_keys or not self.icp_entries:
      return False

    icp_verified = 0
    for icp_entry in self.icp_entries:
      verified = False
      for pub_key in transparency_log_pub_keys:
        if icp_entry.verify_vbmeta_image(vbmeta_image, pub_key):
          verified = True
          break
      if verified:
        icp_verified += 1
    return icp_verified == len(self.icp_entries)

  def encode(self):
    """Serialize the AftlImage to a bytearray().

    Returns:
      A bytearray() with the encoded AFTL image.

    Raises:
      AftlError: If invalid AFTL image structure.
    """
    # The header and entries are guaranteed to be valid when encode is called.
    # Check the entire structure as a whole.
    if not self.is_valid():
      raise AftlError('Invalid AftlImage structure.')

    aftl_image = bytearray()
    aftl_image.extend(self.image_header.encode())
    for icp_entry in self.icp_entries:
      aftl_image.extend(icp_entry.encode())
    return aftl_image

  def is_valid(self):
    """Ensures that values in the AftlImage are sane.

    Returns:
      True if the values in the AftlImage are sane, False otherwise.
    """
    if not self.image_header.is_valid():
      return False

    if self.image_header.icp_count != len(self.icp_entries):
      return False

    for icp_entry in self.icp_entries:
      if not icp_entry.is_valid():
        return False
    return True

  def print_desc(self, o):
    """Print the AFTL image.

    Arguments:
      o: The object to write the output to.
    """
    o.write('Android Firmware Transparency Image:\n')
    self.image_header.print_desc(o)
    for i, icp_entry in enumerate(self.icp_entries):
      o.write('  Entry #{}:\n'.format(i + 1))
      icp_entry.print_desc(o)


class AftlCommunication(object):
  """Class to abstract the communication layer with the transparency log."""

  def __init__(self, transparency_log_config, timeout):
    """Initializes the object.

    Arguments:
      transparency_log_config: A TransparencyLogConfig instance.
      timeout: Duration in seconds before requests to the AFTL times out. A
        value of 0 or None means there will be no timeout.
    """
    self.transparency_log_config = transparency_log_config
    if timeout:
      self.timeout = timeout
    else:
      self.timeout = None

  def add_vbmeta(self, request):
    """Calls the AddVBMeta RPC on the AFTL server.

    Arguments:
      request: An AddVBMetaRequest message.

    Returns:
      An AddVBMetaResponse message.

    Raises:
      AftlError: If grpc or the proto modules cannot be loaded, if there is an
        error communicating with the log.
    """
    raise NotImplementedError(
        'add_vbmeta() needs to be implemented by subclass.')


class AftlGrpcCommunication(AftlCommunication):
  """Class that implements GRPC communication to the AFTL server."""

  def add_vbmeta(self, request):
    """Calls the AddVBMeta RPC on the AFTL server.

    Arguments:
      request: An AddVBMetaRequest message.

    Returns:
      An AddVBMetaResponse message.

    Raises:
      AftlError: If grpc or the proto modules cannot be loaded, if there is an
        error communicating with the log.
    """
    # Import grpc now to avoid global dependencies as it otherwise breaks
    # running unittest with atest.
    try:
      import grpc  # pylint: disable=import-outside-toplevel
      from proto import api_pb2_grpc # pylint: disable=import-outside-toplevel
    except ImportError as e:
      err_str = 'grpc can be installed with python pip install grpcio.\n'
      raise AftlError('Failed to import module: ({}).\n{}'.format(e, err_str))

    # Set up the gRPC channel with the transparency log.
    sys.stdout.write('Preparing to request inclusion proof from {}. This could '
                     'take ~30 seconds for the process to complete.\n'.format(
                         self.transparency_log_config.target))
    channel = grpc.insecure_channel(self.transparency_log_config.target)
    stub = api_pb2_grpc.AFTLogStub(channel)

    metadata = []
    if self.transparency_log_config.api_key:
      metadata.append(('x-api-key', self.transparency_log_config.api_key))

    # Attempt to transmit to the transparency log.
    sys.stdout.write('ICP is about to be requested from transparency log '
                     'with domain {}.\n'.format(
                         self.transparency_log_config.target))
    try:
      response = stub.AddVBMeta(request, timeout=self.timeout,
                                metadata=metadata)
    except grpc.RpcError as e:
      raise AftlError('Error: grpc failure ({})'.format(e))
    return response


class Aftl(avbtool.Avb):
  """Business logic for aftltool command-line tool."""

  def get_vbmeta_image(self, image_filename):
    """Gets the VBMeta struct bytes from image.

    Arguments:
      image_filename: Image file to get information from.

    Returns:
      A tuple with following elements:
        1. A bytearray with the vbmeta structure or None if the file does not
           contain a VBMeta structure.
        2. The VBMeta image footer.
    """
    # Reads and parses the vbmeta image.
    try:
      image = avbtool.ImageHandler(image_filename, read_only=True)
    except (IOError, ValueError) as e:
      sys.stderr.write('The image does not contain a valid VBMeta structure: '
                       '{}.\n'.format(e))
      return None, None

    try:
      (footer, header, _, _) = self._parse_image(image)
    except avbtool.AvbError as e:
      sys.stderr.write('The image cannot be parsed: {}.\n'.format(e))
      return None, None

    # Seeks for the start of the vbmeta image and calculates its size.
    offset = 0
    if footer:
      offset = footer.vbmeta_offset
    vbmeta_image_size = (offset + header.SIZE
                         + header.authentication_data_block_size
                         + header.auxiliary_data_block_size)

    # Reads the vbmeta image bytes.
    try:
      image.seek(offset)
    except RuntimeError as e:
      sys.stderr.write('Given vbmeta image offset is invalid: {}.\n'.format(e))
      return None, None
    return image.read(vbmeta_image_size), footer

  def get_aftl_image(self, image_filename):
    """Gets the AftlImage from image.

    Arguments:
      image_filename: Image file to get information from.

    Returns:
      An AftlImage or None if the file does not contain a AftlImage.
    """
    # Reads the vbmeta image bytes.
    vbmeta_image, _ = self.get_vbmeta_image(image_filename)
    if not vbmeta_image:
      return None

    try:
      image = avbtool.ImageHandler(image_filename, read_only=True)
    except ValueError as e:
      sys.stderr.write('The image does not contain a valid VBMeta structure: '
                       '{}.\n'.format(e))
      return None

    # Seeks for the start of the AftlImage.
    try:
      image.seek(len(vbmeta_image))
    except RuntimeError as e:
      sys.stderr.write('Given AftlImage image offset is invalid: {}.\n'
                       .format(e))
      return None

    # Parses the header for the AftlImage size.
    tmp_header_bytes = image.read(AftlImageHeader.SIZE)
    if not tmp_header_bytes or len(tmp_header_bytes) != AftlImageHeader.SIZE:
      sys.stderr.write('This image does not contain an AftlImage.\n')
      return None

    try:
      tmp_header = AftlImageHeader(tmp_header_bytes)
    except AftlError as e:
      sys.stderr.write('This image does not contain a valid AftlImage: '
                       '{}.\n'.format(e))
      return None

    # Resets to the beginning of the AftlImage.
    try:
      image.seek(len(vbmeta_image))
    except RuntimeError as e:
      sys.stderr.write('Given AftlImage image offset is invalid: {}.\n'
                       .format(e))
      return None

    # Parses the full AftlImage.
    aftl_image_bytes = image.read(tmp_header.aftl_image_size)
    aftl_image = None
    try:
      aftl_image = AftlImage(aftl_image_bytes)
    except AftlError as e:
      sys.stderr.write('The image does not contain a valid AftlImage: '
                       '{}.\n'.format(e))
    return aftl_image

  def info_image_icp(self, vbmeta_image_path, output):
    """Implements the 'info_image_icp' command.

    Arguments:
      vbmeta_image_path: Image file to get information from.
      output: Output file to write human-readable information to (file object).

    Returns:
      True if the given image has an AftlImage and could successfully
      be processed; otherwise False.
    """
    aftl_image = self.get_aftl_image(vbmeta_image_path)
    if not aftl_image:
      return False
    aftl_image.print_desc(output)
    return True

  def verify_image_icp(self, vbmeta_image_path, transparency_log_pub_keys,
                       output):
    """Implements the 'verify_image_icp' command.

    Arguments:
      vbmeta_image_path: Image file to get information from.
      transparency_log_pub_keys: List of paths to PEM files containing trusted
        public keys that correspond with the transparency_logs.
      output: Output file to write human-readable information to (file object).

    Returns:
      True if for the given image the inclusion proof validates; otherwise
      False.
    """
    vbmeta_image, _ = self.get_vbmeta_image(vbmeta_image_path)
    aftl_image = self.get_aftl_image(vbmeta_image_path)
    if not aftl_image or not vbmeta_image:
      return False
    verified = aftl_image.verify_vbmeta_image(vbmeta_image,
                                              transparency_log_pub_keys)
    if not verified:
      output.write('The inclusion proofs for the image do not validate.\n')
      return False
    output.write('The inclusion proofs for the image successfully validate.\n')
    return True

  def request_inclusion_proof(self, transparency_log_config, vbmeta_image,
                              version_inc, manufacturer_key_path,
                              signing_helper, signing_helper_with_files,
                              timeout, aftl_comms=None):
    """Packages and sends a request to the specified transparency log.

    Arguments:
      transparency_log_config: A TransparencyLogConfig instance.
      vbmeta_image: A bytearray with the VBMeta image.
      version_inc: Subcomponent of the build fingerprint.
      manufacturer_key_path: Path to key used to sign messages sent to the
        transparency log servers.
      signing_helper: Program which signs a hash and returns a signature.
      signing_helper_with_files: Same as signing_helper but uses files instead.
      timeout: Duration in seconds before requests to the transparency log
        timeout.
      aftl_comms: A subclass of the AftlCommunication class. The default is
        to use AftlGrpcCommunication.

    Returns:
      An AftlIcpEntry with the inclusion proof for the log entry.

    Raises:
      AftlError: If grpc or the proto modules cannot be loaded, if there is an
         error communicating with the log, if the manufacturer_key_path
         cannot be decoded, or if the log submission cannot be signed.
    """
    # Calculate the hash of the vbmeta image.
    vbmeta_hash = hashlib.sha256(vbmeta_image).digest()

    # Extract the key data from the PEM file if of size 4096.
    manufacturer_key = avbtool.RSAPublicKey(manufacturer_key_path)
    if manufacturer_key.num_bits != 4096:
      raise AftlError('Manufacturer keys not of size 4096: {}'.format(
          manufacturer_key.num_bits))
    manufacturer_key_data = rsa_key_read_pem_bytes(manufacturer_key_path)

    # Calculate the hash of the manufacturer key data.
    m_key_hash = hashlib.sha256(manufacturer_key_data).digest()

    # Build VBMetaPrimaryAnnotation with that data.
    annotation = VBMetaPrimaryAnnotation(
        vbmeta_hash=vbmeta_hash, version_incremental=version_inc,
        manufacturer_key_hash=m_key_hash)

    # Sign annotation and add it to the request.
    signed_annotation = annotation.sign(
        manufacturer_key_path, signing_helper=signing_helper,
        signing_helper_with_files=signing_helper_with_files)

    encoded_signed_annotation = io.BytesIO()
    signed_annotation.encode(encoded_signed_annotation)
    request = api_pb2.AddVBMetaRequest(
        vbmeta=vbmeta_image,
        signed_vbmeta_primary_annotation=encoded_signed_annotation.getvalue())

    # Submit signed VBMeta annotation to the server.
    if not aftl_comms:
      aftl_comms = AftlGrpcCommunication(transparency_log_config, timeout)
    response = aftl_comms.add_vbmeta(request)

    # Return an AftlIcpEntry representing this response.
    icp_entry = AftlIcpEntry()
    icp_entry.translate_response(transparency_log_config.target, response)
    return icp_entry

  def make_icp_from_vbmeta(self, vbmeta_image_path, output,
                           signing_helper, signing_helper_with_files,
                           version_incremental, transparency_log_configs,
                           manufacturer_key, padding_size, timeout):
    """Generates a vbmeta image with inclusion proof given a vbmeta image.

    The AftlImage contains the information required to validate an inclusion
    proof for a specific vbmeta image. It consists of a header (struct
    AftlImageHeader) and zero or more entry structures (struct AftlIcpEntry)
    that contain the vbmeta leaf hash, tree size, root hash, inclusion proof
    hashes, and the signature for the root hash.

    The vbmeta image, its hash, the version_incremental part of the build
    fingerprint, and the hash of the manufacturer key are sent to the
    transparency log, with the message signed by the manufacturer key.
    An inclusion proof is calculated and returned. This inclusion proof is
    then packaged in an AftlImage structure. The existing vbmeta data is
    copied to a new file, appended with the AftlImage data, and written to
    output. Validation of the inclusion proof does not require
    communication with the transparency log.

    Arguments:
      vbmeta_image_path: Path to a vbmeta image file.
      output: File to write the results to.
      signing_helper: Program which signs a hash and returns a signature.
      signing_helper_with_files: Same as signing_helper but uses files instead.
      version_incremental: A string representing the subcomponent of the
        build fingerprint used to identify the vbmeta in the transparency log.
      transparency_log_configs: List of TransparencyLogConfig used to request
        the inclusion proofs.
      manufacturer_key: Path to PEM file containting the key file used to sign
        messages sent to the transparency log servers.
      padding_size: If not 0, pads output so size is a multiple of the number.
      timeout: Duration in seconds before requests to the AFTL times out. A
        value of 0 or None means there will be no timeout.

    Returns:
      True if the inclusion proofs could be fetched from the transparency log
      servers and could be successfully validated; otherwise False.
    """
    # Retrieves vbmeta structure from given partition image.
    vbmeta_image, footer = self.get_vbmeta_image(vbmeta_image_path)

    # Fetches inclusion proofs for vbmeta structure from all transparency logs.
    aftl_image = AftlImage()
    for log_config in transparency_log_configs:
      try:
        icp_entry = self.request_inclusion_proof(log_config, vbmeta_image,
                                                 version_incremental,
                                                 manufacturer_key,
                                                 signing_helper,
                                                 signing_helper_with_files,
                                                 timeout)
        if not icp_entry.verify_vbmeta_image(vbmeta_image, log_config.pub_key):
          sys.stderr.write('The inclusion proof from {} could not be verified.'
                           '\n'.format(log_config.target))
        aftl_image.add_icp_entry(icp_entry)
      except AftlError as e:
        # The inclusion proof request failed. Continue and see if others will.
        sys.stderr.write('Requesting inclusion proof failed: {}.\n'.format(e))
        continue

    # Checks that the resulting AftlImage is sane.
    if aftl_image.image_header.icp_count != len(transparency_log_configs):
      sys.stderr.write('Valid inclusion proofs could only be retrieved from {} '
                       'out of {} transparency logs.\n'
                       .format(aftl_image.image_header.icp_count,
                               len(transparency_log_configs)))
      return False
    if not aftl_image.is_valid():
      sys.stderr.write('Resulting AftlImage structure is malformed.\n')
      return False
    keys = [log.pub_key for log in transparency_log_configs]
    if not aftl_image.verify_vbmeta_image(vbmeta_image, keys):
      sys.stderr.write('Resulting AftlImage inclusion proofs do not '
                       'validate.\n')
      return False

    # Writes original VBMeta image, followed by the AftlImage into the output.
    if footer:  # Checks if it is a chained partition.
      # TODO(b/147217370): Determine the best way to handle chained partitions
      # like the system.img. Currently, we only put the main vbmeta.img in the
      # transparency log.
      sys.stderr.write('Image has a footer and ICP for this format is not '
                       'implemented.\n')
      return False

    output.seek(0)
    output.write(vbmeta_image)
    encoded_aftl_image = aftl_image.encode()
    output.write(encoded_aftl_image)

    if padding_size > 0:
      total_image_size = len(vbmeta_image) + len(encoded_aftl_image)
      padded_size = avbtool.round_to_multiple(total_image_size, padding_size)
      padding_needed = padded_size - total_image_size
      output.write('\0' * padding_needed)

    sys.stdout.write('VBMeta image with AFTL image successfully created.\n')
    return True

  def _load_test_process_function(self, vbmeta_image_path,
                                  transparency_log_config,
                                  manufacturer_key,
                                  process_number, submission_count,
                                  preserve_icp_images, timeout, result_queue):
    """Function to be used by multiprocessing.Process.

    Arguments:
      vbmeta_image_path: Path to a vbmeta image file.
      transparency_log_config: A TransparencyLogConfig instance used to request
        an inclusion proof.
      manufacturer_key: Path to PEM file containting the key file used to sign
        messages sent to the transparency log servers.
      process_number: The number of the processes executing the function.
      submission_count: Number of total submissions to perform per
        process_count.
      preserve_icp_images: Boolean to indicate if the generated vbmeta image
        files with inclusion proofs should be preserved in the temporary
        directory.
      timeout: Duration in seconds before requests to the AFTL times out. A
        value of 0 or None means there will be no timeout.
      result_queue: Multiprocessing.Queue object for posting execution results.
    """
    for count in range(0, submission_count):
      version_incremental = 'aftl_load_testing_{}_{}'.format(process_number,
                                                             count)
      output_file = os.path.join(tempfile.gettempdir(),
                                 '{}_icp.img'.format(version_incremental))
      output = open(output_file, 'wb')

      # Instrumented section.
      start_time = time.time()
      result = self.make_icp_from_vbmeta(
          vbmeta_image_path=vbmeta_image_path,
          output=output,
          signing_helper=None,
          signing_helper_with_files=None,
          version_incremental=version_incremental,
          transparency_log_configs=[transparency_log_config],
          manufacturer_key=manufacturer_key,
          padding_size=0,
          timeout=timeout)
      end_time = time.time()

      output.close()
      if not preserve_icp_images:
        os.unlink(output_file)

      # Puts the result onto the result queue.
      execution_time = end_time - start_time
      result_queue.put((start_time, end_time, execution_time,
                        version_incremental, result))

  def load_test_aftl(self, vbmeta_image_path, output, transparency_log_config,
                     manufacturer_key,
                     process_count, submission_count, stats_filename,
                     preserve_icp_images, timeout):
    """Performs multi-threaded load test on a given AFTL and prints stats.

    Arguments:
      vbmeta_image_path: Path to a vbmeta image file.
      output: File to write the report to.
      transparency_log_config: A TransparencyLogConfig used to request an
        inclusion proof.
      manufacturer_key: Path to PEM file containting the key file used to sign
        messages sent to the transparency log servers.
      process_count: Number of processes used for parallel testing.
      submission_count: Number of total submissions to perform per
        process_count.
      stats_filename: Path to the stats file to write the raw execution data to.
        If None, it will be written to the temp directory.
      preserve_icp_images: Boolean to indicate if the generated vbmeta
        image files with inclusion proofs should preserved.
      timeout: Duration in seconds before requests to the AFTL times out. A
        value of 0 or None means there will be no timeout.

    Returns:
      True if the load tested succeeded without errors; otherwise False.
    """
    if process_count < 1 or submission_count < 1:
      sys.stderr.write('Values for --processes/--submissions '
                       'must be at least 1.\n')
      return False

    if not stats_filename:
      stats_filename = os.path.join(
          tempfile.gettempdir(),
          'load_test_p{}_s{}.csv'.format(process_count, submission_count))

    stats_file = None
    try:
      stats_file = open(stats_filename, 'wt')
      stats_file.write('start_time,end_time,execution_time,version_incremental,'
                       'result\n')
    except IOError as e:
      sys.stderr.write('Could not open stats file {}: {}.\n'
                       .format(stats_file, e))
      return False

    # Launch all the processes with their workloads.
    result_queue = multiprocessing.Queue()
    processes = set()
    execution_times = []
    results = []
    for i in range(0, process_count):
      p = multiprocessing.Process(
          target=self._load_test_process_function,
          args=(vbmeta_image_path, transparency_log_config,
                manufacturer_key, i, submission_count,
                preserve_icp_images, timeout, result_queue))
      p.start()
      processes.add(p)

    while processes:
      # Processes the results queue and writes these to a stats file.
      try:
        (start_time, end_time, execution_time, version_incremental,
         result) = result_queue.get(timeout=1)
        stats_file.write('{},{},{},{},{}\n'.format(start_time, end_time,
                                                   execution_time,
                                                   version_incremental, result))
        execution_times.append(execution_time)
        results.append(result)
      except queue.Empty:
        pass

      # Checks if processes are still alive; if not clean them up. join() would
      # have been nicer but we want to continously stream out the stats to file.
      for p in processes.copy():
        if not p.is_alive():
          processes.remove(p)

    # Prepares stats.
    executions = sorted(execution_times)
    execution_count = len(execution_times)
    median = 0

    # pylint: disable=old-division
    if execution_count % 2 == 0:
      median = (executions[execution_count // 2 - 1]
                + executions[execution_count // 2]) / 2
    else:
      median = executions[execution_count // 2]

    # Outputs the stats report.
    o = output
    o.write('Load testing results:\n')
    o.write('  Processes:               {}\n'.format(process_count))
    o.write('  Submissions per process: {}\n'.format(submission_count))
    o.write('\n')
    o.write('  Submissions:\n')
    o.write('    Total:                 {}\n'.format(len(executions)))
    o.write('    Succeeded:             {}\n'.format(results.count(True)))
    o.write('    Failed:                {}\n'.format(results.count(False)))
    o.write('\n')
    o.write('  Submission execution durations:\n')
    o.write('    Average:               {:.2f} sec\n'.format(
        sum(execution_times) / execution_count))
    o.write('    Median:                {:.2f} sec\n'.format(median))
    o.write('    Min:                   {:.2f} sec\n'.format(min(executions)))
    o.write('    Max:                   {:.2f} sec\n'.format(max(executions)))

    # Close the stats file.
    stats_file.close()
    if results.count(False):
      return False
    return True


class TransparencyLogConfig(object):
  """Class that gathers the fields representing a transparency log.

  Attributes:
    target: The hostname and port of the server in hostname:port format.
    pub_key: A PEM file that contains the public key of the transparency
      log server.
    api_key: The API key to use to interact with the transparency log
      server.
  """

  @staticmethod
  def from_argument(arg):
    """Build an object from a command line argument string.

    Arguments:
      arg: The transparency log as passed in the command line argument.
        It must be in the format: host:port,key_file[,api_key].

    Returns:
      The TransparencyLogConfig instance.

    Raises:
      argparse.ArgumentTypeError: If the format of arg is invalid.
    """
    api_key = None
    try:
      target, pub_key, *rest = arg.split(",", maxsplit=2)
    except ValueError:
      raise argparse.ArgumentTypeError("incorrect format for transparency log "
                                       "server, expected "
                                       "host:port,publickey_file.")
    if not target:
      raise argparse.ArgumentTypeError("incorrect format for transparency log "
                                       "server: host:port cannot be empty.")
    if not pub_key:
      raise argparse.ArgumentTypeError("incorrect format for transparency log "
                                       "server: publickey_file cannot be "
                                       "empty.")
    if rest:
      api_key = rest[0]
    return TransparencyLogConfig(target, pub_key, api_key)

  def __init__(self, target, pub_key, api_key=None):
    """Initializes a new TransparencyLogConfig object."""
    self.target = target
    self.pub_key = pub_key
    self.api_key = api_key


class AftlTool(avbtool.AvbTool):
  """Object for aftltool command-line tool."""

  def __init__(self):
    """Initializer method."""
    self.aftl = Aftl()
    super(AftlTool, self).__init__()

  def make_icp_from_vbmeta(self, args):
    """Implements the 'make_icp_from_vbmeta' sub-command."""
    args = self._fixup_common_args(args)
    return self.aftl.make_icp_from_vbmeta(args.vbmeta_image_path,
                                          args.output,
                                          args.signing_helper,
                                          args.signing_helper_with_files,
                                          args.version_incremental,
                                          args.transparency_log_servers,
                                          args.manufacturer_key,
                                          args.padding_size,
                                          args.timeout)

  def info_image_icp(self, args):
    """Implements the 'info_image_icp' sub-command."""
    return self.aftl.info_image_icp(args.vbmeta_image_path.name, args.output)

  def verify_image_icp(self, args):
    """Implements the 'verify_image_icp' sub-command."""
    return self.aftl.verify_image_icp(args.vbmeta_image_path.name,
                                      args.transparency_log_pub_keys,
                                      args.output)

  def load_test_aftl(self, args):
    """Implements the 'load_test_aftl' sub-command."""
    return self.aftl.load_test_aftl(args.vbmeta_image_path,
                                    args.output,
                                    args.transparency_log_server,
                                    args.manufacturer_key,
                                    args.processes,
                                    args.submissions,
                                    args.stats_file,
                                    args.preserve_icp_images,
                                    args.timeout)

  def run(self, argv):
    """Command-line processor.

    Arguments:
      argv: Pass sys.argv from main.
    """
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title='subcommands')

    # Command: make_icp_from_vbmeta
    sub_parser = subparsers.add_parser('make_icp_from_vbmeta',
                                       help='Makes an ICP enhanced vbmeta image'
                                       ' from an existing vbmeta image.')
    sub_parser.add_argument('--output',
                            help='Output file name.',
                            type=argparse.FileType('wb'),
                            default=sys.stdout)
    sub_parser.add_argument('--vbmeta_image_path',
                            help='Path to a generate vbmeta image file.',
                            required=True)
    sub_parser.add_argument('--version_incremental',
                            help='Current build ID.',
                            required=True)
    sub_parser.add_argument('--manufacturer_key',
                            help='Path to the PEM file containing the '
                            'manufacturer key for use with the log.',
                            required=True)
    sub_parser.add_argument('--transparency_log_servers',
                            help='List of transparency log servers in '
                            'host:port,publickey_file[,api_key] format. The '
                            'publickey_file must be in the PEM format.',
                            nargs='+', type=TransparencyLogConfig.from_argument)
    sub_parser.add_argument('--padding_size',
                            metavar='NUMBER',
                            help='If non-zero, pads output with NUL bytes so '
                            'its size is a multiple of NUMBER (default: 0)',
                            type=avbtool.parse_number,
                            default=0)
    sub_parser.add_argument('--timeout',
                            metavar='SECONDS',
                            help='Timeout in seconds for transparency log '
                            'requests (default: 600 sec). A value of 0 means '
                            'no timeout.',
                            type=avbtool.parse_number,
                            default=600)
    self._add_common_args(sub_parser)
    sub_parser.set_defaults(func=self.make_icp_from_vbmeta)

    # Command: info_image_icp
    sub_parser = subparsers.add_parser(
        'info_image_icp',
        help='Show information about AFTL ICPs in vbmeta or footer.')
    sub_parser.add_argument('--vbmeta_image_path',
                            help='Path to vbmeta image for AFTL information.',
                            type=argparse.FileType('rb'),
                            required=True)
    sub_parser.add_argument('--output',
                            help='Write info to file',
                            type=argparse.FileType('wt'),
                            default=sys.stdout)
    sub_parser.set_defaults(func=self.info_image_icp)

    # Arguments for verify_image_icp.
    sub_parser = subparsers.add_parser(
        'verify_image_icp',
        help='Verify AFTL ICPs in vbmeta or footer.')

    sub_parser.add_argument('--vbmeta_image_path',
                            help='Image to verify the inclusion proofs.',
                            type=argparse.FileType('rb'),
                            required=True)
    sub_parser.add_argument('--transparency_log_pub_keys',
                            help='Paths to PEM files containing transparency '
                            'log server key(s). This must not be None.',
                            nargs='*',
                            required=True)
    sub_parser.add_argument('--output',
                            help='Write info to file',
                            type=argparse.FileType('wt'),
                            default=sys.stdout)
    sub_parser.set_defaults(func=self.verify_image_icp)

    # Command: load_test_aftl
    sub_parser = subparsers.add_parser(
        'load_test_aftl',
        help='Perform load testing against one AFTL log server. Note: This MUST'
        ' not be performed against a production system.')
    sub_parser.add_argument('--vbmeta_image_path',
                            help='Path to a generate vbmeta image file.',
                            required=True)
    sub_parser.add_argument('--output',
                            help='Write report to file.',
                            type=argparse.FileType('wt'),
                            default=sys.stdout)
    sub_parser.add_argument('--manufacturer_key',
                            help='Path to the PEM file containing the '
                            'manufacturer key for use with the log.',
                            required=True)
    sub_parser.add_argument('--transparency_log_server',
                            help='Transparency log server to test against in '
                            'host:port,publickey_file[,api_key] format. The '
                            'publickey_file must be in the PEM format.',
                            required=True,
                            type=TransparencyLogConfig.from_argument)
    sub_parser.add_argument('--processes',
                            help='Number of parallel processes to use for '
                            'testing (default: 1).',
                            type=avbtool.parse_number,
                            default=1)
    sub_parser.add_argument('--submissions',
                            help='Number of submissions to perform against the '
                            'log per process (default: 1).',
                            type=avbtool.parse_number,
                            default=1)
    sub_parser.add_argument('--stats_file',
                            help='Path to the stats file to write the raw '
                            'execution data to (Default: '
                            'load_test_p[processes]_s[submissions].csv.')
    sub_parser.add_argument('--preserve_icp_images',
                            help='Boolean flag to indicate if the generated '
                            'vbmeta image files with inclusion proofs should '
                            'preserved.',
                            action='store_true')
    sub_parser.add_argument('--timeout',
                            metavar='SECONDS',
                            help='Timeout in seconds for transparency log '
                            'requests (default: 0). A value of 0 means '
                            'no timeout.',
                            type=avbtool.parse_number,
                            default=0)
    sub_parser.set_defaults(func=self.load_test_aftl)

    args = parser.parse_args(argv[1:])
    if not 'func' in args:
      # This error gets raised when the command line tool is called without any
      # arguments. It mimics the original Python 2 behavior.
      parser.print_usage()
      print('aftltool: error: too few arguments')
      sys.exit(2)
    try:
      success = args.func(args)
    except AftlError as e:
      # Signals to calling tools that an unhandled exception occured.
      sys.stderr.write('Unhandled AftlError occured: {}\n'.format(e))
      sys.exit(2)

    if not success:
      # Signals to calling tools that the command has failed.
      sys.exit(1)

if __name__ == '__main__':
  tool = AftlTool()
  tool.run(sys.argv)
