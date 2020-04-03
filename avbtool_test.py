#!/usr/bin/env python

# Copyright 2019, The Android Open Source Project
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
"""Unit tests for avbtool for supporting the migration from Python 2.7 to 3."""

# pylint: disable=unused-import
from __future__ import print_function

import base64
import binascii
import io
import os
import sys
import unittest

import avbtool


# Workaround for b/149307145 in order to pick up the test data from the right
# location independent where the script is called from.
# TODO(b/149307145): Remove workaround once the referenced bug is fixed.
TEST_EXEC_PATH = os.path.dirname(os.path.realpath(__file__))


class AvbtoolTestCase(unittest.TestCase):

  def testX(self):
    pass

if __name__ == '__main__':
  unittest.main(verbosity=2)
