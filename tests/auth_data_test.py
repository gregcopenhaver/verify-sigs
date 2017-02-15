#!/usr/bin/env python

# Copyright 2012 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: caronni@google.com (Germano Caronni)

"""Test for auth_data parser of Authenticode signatures."""

import os
import pickle
import time
import unittest as test

from verifysigs.utils import pecoff_blob, auth_data


# EVIL EVIL -- Monkeypatch to extend accessor
# TODO(user): This was submitted to pyasn1. Remove when we have it back.
def F(self, idx):
  if type(idx) is int:
    return self.getComponentByPosition(idx)
  else: return self.getComponentByName(idx)
from pyasn1.type import univ  # pylint: disable-msg=C6204,C6203
univ.SequenceAndSetBase.__getitem__ = F
del F, univ
# EVIL EVIL


class AuthenticodeTest(test.TestCase):

  def testRunTestData(self):
    # Walk through one data file in the test_data folder, and compare output
    # with precomputed expected output.
    data_file = os.path.join('data', 'SoftwareUpdate.exe.res')

    with open(data_file, 'rb') as resf:
      exp_results = pickle.load(resf)

    # Make sure we have loaded the right data.
    expected_generic_sha1 = b'\x83\x22\xf1\xc2\xc3\x55\xd8\x84\x32\xf1\xf0\x3a\x1f\x23\x1f\x63\x91\x21\x86\xbd'
    loaded_generic_hashes = [x for x in exp_results if x['name'] == 'generic']
    loaded_generic_sha1 = loaded_generic_hashes[0]['sha1']
    self.assertEqual(expected_generic_sha1, loaded_generic_sha1)

    signed_pecoffs = [x for x in exp_results if x['name'] == 'pecoff' and
                      'SignedData' in x]
    # If the invoker of the fingerprinter specified multiple fingers for pecoff
    # hashing (possible, even if not sensible), then there can be more than one
    # entry in this list. Should not be the case for this sample.
    self.assertEqual(len(signed_pecoffs), 1)
    signed_pecoff = signed_pecoffs[0]

    # Make sure PE/COFF hashes match as well. Again, just a sanity check.
    expected_auth_sha1 = b'\x97\x8b\x90\xac\xe9\x9c\x76\x48\x41\xd2\xdd\x17\xd2\x78\xfa\xc4\x14\x99\x62\xa3'
    loaded_auth_sha1 = signed_pecoff['sha1']
    self.assertEqual(expected_auth_sha1, loaded_auth_sha1)

    signed_datas = signed_pecoff['SignedData']
    # There may be multiple of these, if the windows binary was signed multiple
    # times, e.g. by different entities. Each of them adds a complete SignedData
    # blob to the binary. For our sample, there is only one blob.
    self.assertEqual(len(signed_datas), 1)
    signed_data = signed_datas[0]

    blob = pecoff_blob.PecoffBlob(signed_data)

    auth = auth_data.AuthData(blob.getcertificateblob())
    content_hasher_name = auth.digest_algorithm().name
    computed_content_hash = signed_pecoff[content_hasher_name]

    try:
      auth.validateasn1()
      auth.validatehashes(computed_content_hash)
      auth.validatesignatures()
      auth.validatecertchains(time.gmtime())
    except auth_data.Asn1Error:
      if auth.openssl_error:
        print('OpenSSL Errors:\n%s' % auth.openssl_error)
      raise

    print('Program: %s, URL: %s' % (auth.program_name, auth.program_url))
    print('countersig: %d' % auth.has_countersignature)
    print('Timestamp: %s' % auth.counter_timestamp)

    self.assertEqual(auth.trailing_data, b'\x00')


def main():
  test.main()

if __name__ == '__main__':
  main()
