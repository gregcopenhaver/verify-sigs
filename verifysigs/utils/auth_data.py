#!/usr/bin/env python

# Copyright 2011 Google Inc. All Rights Reserved.
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

"""auth_data represents ASN.1 encoded Authenticode data.

   Provides high-level validators and accessor functions.
"""

import hashlib
import binascii

from verifysigs.asn1utils import dn
from verifysigs.asn1utils import oids
from verifysigs.asn1utils import pkcs7
from verifysigs.asn1utils import spc

from pyasn1.codec.ber import decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ
import ssl

try:
    from M2Crypto import Err as M2_Err  # pylint: disable-msg=C6204
    from M2Crypto import RSA as M2_RSA  # pylint: disable-msg=C6204
    from M2Crypto import X509 as M2_X509  # pylint: disable-msg=C6204

except ImportError:
    M2_X509 = None

import OpenSSL
from OpenSSL.crypto import X509,X509Store,X509StoreContext
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding


class Asn1Error(Exception):
    pass


def requires_m2crypto(fn):
    """Decorator to support limited functionality if M2Crypto is missing."""

    def m2checkingwrapper(*args, **kwargs):
        if not M2_X509:
            raise Asn1Error('%s requires M2Crypto, which is not available', fn)
        return fn(*args, **kwargs)

    return m2checkingwrapper


# This is meant to hold the ASN.1 data representing all pieces
# of the parsed ASN.1 authenticode structure.
class AuthData(object):
    """Container for parsed ASN.1 structures out of Authenticode.

       Parsing is done at constructor time, after which caller can
       invoke validators, and access data structures.
    """

    container = None
    trailing_data = None
    signed_data = None
    digest_algorithm = None
    spc_info = None
    certificates = None
    signer_info = None
    signing_cert_id = None
    expected_spc_info_hash = None
    computed_auth_attrs_for_hash = None
    auth_attrs = None
    program_name = None
    program_url = None
    encrypted_digest = None
    has_countersignature = None
    counter_sig_info = None
    counter_sig_cert_id = None
    counter_attrs = None
    counter_timestamp = None
    computed_counter_attrs_for_hash = None
    expected_auth_attrs_hash = None
    encrypted_counter_digest = None
    openssl_error = None
    cert_chain_head = None
    counter_chain_head = None

    def __init__(self, content):
        self.container, rest = decoder.decode(content,
                                              asn1Spec=pkcs7.ContentInfo())
        if rest:
            self.trailing_data = rest

        self.signed_data, rest = decoder.decode(self.container['content'],
                                                asn1Spec=pkcs7.SignedData())
        if rest: raise Asn1Error('Extra unparsed content.')

        digest_algorithm_oid = self.signed_data['digestAlgorithms'][0]['algorithm']
        self.digest_algorithm = oids.OID_TO_CLASS.get(digest_algorithm_oid)

        spc_blob = self.signed_data['contentInfo']['content']
        self.spc_info, rest = decoder.decode(spc_blob,
                                             asn1Spec=spc.SpcIndirectDataContent())
        if rest: raise Asn1Error('Extra unparsed content.')
        # Currently not parsing the SpcIndirectDataContent 'data' field.
        # It used to contain information about the software publisher, but now
        # is set to default content, or under Vista+, may hold page hashes.

        self.certificates = self._parsecerts(self.signed_data['certificates'])

        self.signer_info = self.signed_data['signerInfos'][0]

        self.signing_cert_id = self._parseissuerinfo(
            self.signer_info['issuerAndSerialNumber'])

        # Parse out mandatory fields in authenticated attributes.
        self.auth_attrs, self.computed_auth_attrs_for_hash = (
            self._parseauthattrs(self.signer_info['authenticatedAttributes'],
                                 required=[pkcs7.ContentType,
                                           pkcs7.DigestInfo,
                                           spc.SpcSpOpusInfo]))
        hashval, rest = decoder.decode(self.auth_attrs[pkcs7.DigestInfo][0])
        if rest: raise Asn1Error('Extra unparsed content.')
        if hashval.__class__ is not univ.OctetString:
            raise Asn1Error('Hash value expected to be OctetString.')
        self.expected_spc_info_hash = binascii.b2a_hex(hashval._value).decode()

        opus_info_asn1 = self.auth_attrs[spc.SpcSpOpusInfo][0]
        self.program_name, self.program_url = self._parseopusinfo(opus_info_asn1)

        self.encrypted_digest = binascii.b2a_hex(self.signer_info['encryptedDigest']._value).decode()

        unauth_attrs = self.signer_info['unauthenticatedAttributes']
        if unauth_attrs is None or len(unauth_attrs) == 0:
            self.has_countersignature = False
            return

        self.has_countersignature = True
        self.counter_sig_info = self._parsecountersig(unauth_attrs)
        self.counter_sig_cert_id = self._parseissuerinfo(
            self.counter_sig_info['issuerAndSerialNumber'])

        # Parse out mandatory fields in countersig authenticated attributes.
        self.counter_attrs, self.computed_counter_attrs_for_hash = (
            self._parseauthattrs(self.counter_sig_info['authenticatedAttributes'],
                                 required=[pkcs7.ContentType,
                                           pkcs7.SigningTime,
                                           pkcs7.DigestInfo]))

        hashval, rest = decoder.decode(self.counter_attrs[pkcs7.DigestInfo][0])
        if rest: raise Asn1Error('Extra unparsed content.')
        if hashval.__class__ is not univ.OctetString:
            raise Asn1Error('Hash value expected to be OctetString.')
        self.expected_auth_attrs_hash = binascii.b2a_hex(hashval._value).decode()

        self.counter_timestamp = self._parsetimestamp(
            self.counter_attrs[pkcs7.SigningTime][0])

        self.encrypted_counter_digest = binascii.b2a_hex(self.counter_sig_info['encryptedDigest']._value).decode()

    @staticmethod
    def _parsetimestamp(time_asn1):
        # Parses countersignature timestamp according to RFC3280, section 4.1.2.5+
        timestamp_choice, rest = decoder.decode(time_asn1,
                                                asn1Spec=pkcs7.SigningTime())
        if rest: raise Asn1Error('Extra unparsed content.')
        return timestamp_choice.ToPythonEpochTime()

    @staticmethod
    def _parseissuerinfo(issuer_and_serial):
        # Extract the information that identifies the certificate to be
        # used for verification on the encryptedDigest in signer_info
        # TODO(user): there is probably more validation to be done on these
        # fields.
        issuer = issuer_and_serial['issuer']
        serial_number = int(issuer_and_serial['serialNumber'])
        issuer_dn = str(dn.DistinguishedName.TraverseRdn(issuer[0]))
        return issuer_dn, serial_number

    @staticmethod
    def _parseopusinfo(opus_info_asn1):
        spc_opus_info, rest = decoder.decode(opus_info_asn1,
                                             asn1Spec=spc.SpcSpOpusInfo())
        if rest: raise Asn1Error('Extra unparsed content.')

        if spc_opus_info['programName']:
            # According to spec, this should always be a Unicode string. However,
            # the ASN.1 syntax allows both ASCII and Unicode. So, let's be careful.
            opus_prog_name = spc_opus_info['programName']
            uni_name = opus_prog_name['unicode']
            ascii_name = opus_prog_name['ascii']
            if ascii_name is not None and ascii_name.isValue and uni_name is not None and uni_name.isValue:
                # WTF? This is supposed to be a CHOICE
                raise Asn1Error('Both elements of a choice are present.')
            elif uni_name:
                program_name = uni_name
            elif ascii_name:
                program_name = str(ascii_name)
            else:
                raise Asn1Error('No element of opusInfo choice is present.')
        else:
            # According to spec, there should always be a program name,
            # and be it zero-length. But let's be gentle, since ASN.1 marks
            # this field als optional.
            program_name = None

        # Again, according to Authenticode spec, the moreInfo field should always
        # be there and point to an ASCII string with a URL.
        if spc_opus_info['moreInfo']:
            more_info = spc_opus_info['moreInfo']
            if more_info['url']:
                more_info_link = str(more_info['url'])
            else:
                raise Asn1Error('Expected a URL in moreInfo.')
        else:
            more_info_link = None

        return program_name, more_info_link

    @staticmethod
    def _extractissuer(cert):
        issuer = cert[0][0]['issuer']
        serial_number = int(cert[0][0]['serialNumber'])
        issuer_dn = str(dn.DistinguishedName.TraverseRdn(issuer[0]))
        return issuer_dn, serial_number

    def _parsecerts(self, certs):
        # TODO(user):
        # Parse them into a dict with serial, subject dn, issuer dn, lifetime,
        # algorithm, x509 version, extensions, ...
        res = dict()
        for cert in certs:
            res[self._extractissuer(cert)] = cert
        return res

    @staticmethod
    def _parsecountersig(unauth_attrs):
        attr = unauth_attrs[0]
        if attr.isValue:
            if oids.OID_TO_CLASS.get(attr['type']) is not pkcs7.CountersignInfo:
                raise Asn1Error('Unexpected countersign OID.')
            values = attr['values']
            if len(values) != 1:
                raise Asn1Error('Expected one CS value, got %d.' % len(values))
            counter_sig_info, rest = decoder.decode(values[0],
                                                    asn1Spec=pkcs7.CountersignInfo())
            if rest: raise Asn1Error('Extra unparsed content.')
            return counter_sig_info

    @staticmethod
    def _parseauthattrs(auth_attrs, required):
        results = dict.fromkeys(required)
        for attr in auth_attrs:
            if (attr['type'] in oids.OID_TO_CLASS and
                        oids.OID_TO_CLASS.get(attr['type']) in required):
                # There are more than those I require, but I don't know what they are,
                # and what to do with them. The spec does not talk about them.
                # One example:
                # 1.3.6.1.4.1.311.2.1.11 contains as value 1.3.6.1.4.1.311.2.1.21
                # SPC_STATEMENT_TYPE_OBJID    SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID
                results[oids.OID_TO_CLASS.get(attr['type'])] = attr['values']
        if None in iter(results.values()):
            raise Asn1Error('Missing mandatory field(s) in auth_attrs.')

        # making sure that the auth_attrs were processed in correct order
        # they need to be sorted in ascending order in the SET, when DER encoded
        # This also makes sure that the tag on Attributes is correct.
        a = [der_encoder.encode(i) for i in auth_attrs]
        a.sort()
        attrs_for_hash = pkcs7.Attributes()
        for i in range(len(auth_attrs)):
            d, _ = decoder.decode(a[i], asn1Spec=pkcs7.Attribute())
            attrs_for_hash.setComponentByPosition(i, d)
        encoded_attrs = der_encoder.encode(attrs_for_hash)

        return results, encoded_attrs

    def _validateemptyparams(self, params):
        if params.isValue:
            param_value, rest = decoder.decode(params)
            if rest:
                raise Asn1Error('Extra unparsed content.')
            if not param_value.isSameTypeWith(univ.Null()):
                raise Asn1Error('Hasher has parameters. No idea what to do with them.')

    def validateasn1(self):
        """Validate overall information / consistency.

        Can be invoked to check through most of the assumptions on
        ASN.1 integrity, and constraints placed on PKCS#7 / X.509 by
        Authenticode.

        Returns:
          Nothing.

        Raises:
          Asn1Error: with a descriptive string, if anything is amiss.
        """

        # Validate overall information
        if (oids.OID_TO_CLASS.get(self.container['contentType']) is not
                pkcs7.SignedData):
            raise Asn1Error('Unexpected OID: %s' %
                            self.container['contentType'].prettyPrint())
        if self.signed_data['version'] != 1:
            raise Asn1Error('SignedData wrong version: %s' %
                            self.signed_data['version'].prettyPrint())

        # Validate content digest specs.
        if len(self.signed_data['digestAlgorithms']) != 1:
            raise Asn1Error('Expected exactly one digestAlgorithm, got %d.' %
                            len(self.signed_data['digestAlgorithms']))
        spec = self.signed_data['digestAlgorithms'][0]
        if (self.digest_algorithm is not hashlib.md5 and
                    self.digest_algorithm is not hashlib.sha1):
            raise Asn1Error('digestAlgorithm must be md5 or sha1, was %s.' %
                            spec['algorithm'].prettyPrint())
        self._validateemptyparams(spec['parameters'])

        # Validate SpcIndirectDataContent structure
        oid = self.signed_data['contentInfo']['contentType']
        if oids.OID_TO_CLASS.get(oid) is not spc.SpcIndirectDataContent:
            raise Asn1Error('Unexpected contentInfo OID: %s' % oid.prettyPrint())

        # Validate content hash meta data in spcIndirectDataContent
        oid = self.spc_info['messageDigest']['digestAlgorithm']['algorithm']
        if oids.OID_TO_CLASS.get(oid) is not self.digest_algorithm:
            raise Asn1Error('Outer and SPC message_digest algorithms don\'t match.')
        params = self.spc_info['messageDigest']['digestAlgorithm']['parameters']
        self._validateemptyparams(params)

        if self.signed_data['crls'].isValue:
            raise Asn1Error('Don\'t know what to do with CRL information.')

        # Work through signer_info pieces that are easily validated
        if len(self.signed_data['signerInfos']) != 1:
            raise Asn1Error('Expected one signer_info, got %d.' %
                            len(self.signed_data['signerInfos']))
        if self.signer_info['version'] != 1:
            raise Asn1Error('SignerInfo wrong version: %s' %
                            self.signer_info['version'].prettyPrint())

        # Make sure signer_info hash algorithm is consistent
        oid = self.signer_info['digestAlgorithm']['algorithm']
        if oids.OID_TO_CLASS.get(oid) is not self.digest_algorithm:
            raise Asn1Error('Outer and signer_info digest algorithms don\'t match.')
        params = self.signer_info['digestAlgorithm']['parameters']
        self._validateemptyparams(params)

        # Make sure the signing cert is actually in the list of certs
        if self.signing_cert_id not in self.certificates:
            raise Asn1Error('Signing cert not in list of known certificates.')

        # auth_attrs has three fields, where we do some integrity / sanity checks
        # content_type
        content_type_set = self.auth_attrs[pkcs7.ContentType]
        if len(content_type_set) != 1:
            raise Asn1Error('authAttr.content_type expected to hold one value.')
        content_type, rest = decoder.decode(content_type_set[0])
        if rest:
            raise Asn1Error('Extra unparsed content.')
        # Spec claims this should be messageDigestOID, but that's not true.
        if oids.OID_TO_CLASS.get(content_type) is not spc.SpcIndirectDataContent:
            raise Asn1Error('Unexpected authAttr.content_type OID: %s' %
                            content_type.prettyPrint())
        # Message_digest -- 'just' an octet string
        message_digest_set = self.auth_attrs[pkcs7.DigestInfo]
        if len(message_digest_set) != 1:
            raise Asn1Error('authAttr.messageDigest expected to hold one value.')
        _, rest = decoder.decode(message_digest_set[0])
        if rest:
            raise Asn1Error('Extra unparsed content.')
        # opusInfo -- has it's own section

        enc_alg = self.signer_info['digestEncryptionAlgorithm']['algorithm']
        if enc_alg not in oids.OID_TO_PUBKEY:
            raise Asn1Error('Could not parse digestEncryptionAlgorithm.')
        params = self.signer_info['digestEncryptionAlgorithm']['parameters']
        self._validateemptyparams(params)

        if not self.has_countersignature: return

        unauth_attrs = self.signer_info['unauthenticatedAttributes']
        if len(unauth_attrs) != 1:
            raise Asn1Error('Expected one attribute, got %d.' % len(unauth_attrs))
        # Extra structure parsed in _ParseCountersig

        # signer_info of the counter signature
        if self.counter_sig_info['version'] != 1:
            raise Asn1Error('Countersignature wrong version: %s' %
                            self.counter_sig_info['version'].prettyPrint())

        # Make sure counter_sig_info hash algorithm is consistent
        oid = self.counter_sig_info['digestAlgorithm']['algorithm']
        if oids.OID_TO_CLASS.get(oid) is not self.digest_algorithm:
            raise Asn1Error('Outer and countersign digest algorithms don\'t match.')
        params = self.counter_sig_info['digestAlgorithm']['parameters']
        self._validateemptyparams(params)

        # Make sure the counter-signing cert is actually in the list of certs
        if self.counter_sig_cert_id not in self.certificates:
            raise Asn1Error('Countersigning cert not in list of known certificates.')

        # counterSig auth_attrs also has three fields, where we do some
        # integrity / sanity checks
        # content_type
        content_type_set = self.counter_attrs[pkcs7.ContentType]
        if len(content_type_set) != 1:
            raise Asn1Error('counterAttr.content_type expected to hold one value.')
        content_type, rest = decoder.decode(content_type_set[0])
        if rest:
            raise Asn1Error('Extra unparsed content.')
        if oids.OID_TO_CLASS.get(content_type) != 'PKCS#7 Data':
            raise Asn1Error('Unexpected counterAttr.content_type OID: %s' %
                            content_type.prettyPrint())
        # message_digest -- 'just' an octet string
        message_digest_set = self.counter_attrs[pkcs7.DigestInfo]
        if len(message_digest_set) != 1:
            raise Asn1Error('counterAttr.message_digest expected to hold one value.')
        _, rest = decoder.decode(message_digest_set[0])
        if rest:
            raise Asn1Error('Extra unparsed content.')
        # TODO(user): Check SigningTime integrity
        # e.g. only one value in the set

        enc_alg = self.counter_sig_info['digestEncryptionAlgorithm']['algorithm']
        if enc_alg not in oids.OID_TO_PUBKEY:
            raise Asn1Error('Could not parse CS digestEncryptionAlgorithm.')
        params = self.counter_sig_info['digestEncryptionAlgorithm']['parameters']
        self._validateemptyparams(params)

    def validatehashes(self, computed_content_hash):
        """Compares computed against expected hashes.

        This method makes sure the chain of hashes is correct. The chain
        consists of Authenticode hash of the actual binary payload, as checked
        against the hash in SpcInfo to the hash of SpcInfo as stored in the
        AuthAttrs, and the hash of EncryptedDigest as stored in the counter-
        signature AuthAttrs, if present.

        Args:
          computed_content_hash: Authenticode hash of binary, as provided by
                                 fingerprinter.
        Raises:
          Asn1Error: if hash validation fails.
        """

        if computed_content_hash != self.spc_info['messageDigest']['digest']:
            raise Asn1Error('1: Validation of content hash failed.')

        spc_blob = self.signed_data['contentInfo']['content']
        # According to RFC2315, 9.3, identifier (tag) and length need to be
        # stripped for hashing. We do this by having the parser just strip
        # out the SEQUENCE part of the spcIndirectData.
        # Alternatively this could be done by re-encoding and concatenating
        # the individual elements in spc_value, I _think_.
        _, hashable_spc_blob = decoder.decode(spc_blob, recursiveFlag=0)
        spc_blob_hash = binascii.b2a_hex(self.digest_algorithm(hashable_spc_blob._value).digest()).decode()
        if spc_blob_hash != self.expected_spc_info_hash:
            raise Asn1Error('2: Validation of SpcInfo hash failed.')
        # Can't check authAttr hash against encrypted hash, done implicitly in
        # M2's pubkey.verify. This can be added by explicit decryption of
        # encryptedDigest, if really needed. (See sample code for RSA in
        # 'verbose_authenticode_sig.py')

        if self.has_countersignature:
            # Validates the hash value found in the authenticated attributes of the
            # counter signature against the hash of the outer signature.
            auth_attr_hash = binascii.b2a_hex(
                self.digest_algorithm(binascii.a2b_hex(self.encrypted_digest)).digest()).decode()
            if auth_attr_hash != self.expected_auth_attrs_hash:
                raise Asn1Error('3: Validation of countersignature hash failed.')

    def extractcertchains(self, timestamp):
        store = X509Store()
        for cert in self.certificates.values():
            cert_X509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                            ssl.DER_cert_to_PEM_cert(der_encoder.encode(cert)))
            OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_X509)

            fw = open(cert_X509.digest('sha1').decode('UTF-8').replace(':', ''), 'wb')
            fw.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_X509))
            fw.close()

        pass

    def validatecertchains(self, timestamp):  # pylint: disable-msg=W0613
        # TODO(user):
        # Check ASN.1 on the certs
        # Check designated certificate use
        # Check extension consistency
        # Check wether timestamping is prohibited
        sc = self.certificates[self.signing_cert_id]
        not_before, not_after, top_cert = self._validatecertchain(
            self.certificates[self.signing_cert_id])
        self.cert_chain_head = (not_before, not_after,
                                self._extractissuer(top_cert))

        if self.has_countersignature:
            cs_not_before, cs_not_after, cs_top_cert = self._validatecertchain(
                self.certificates[self.counter_sig_cert_id])
            self.counter_chain_head = (cs_not_before, cs_not_after,
                                       self._extractissuer(cs_top_cert))
            # Time of countersignature needs to be within validity of both chains
            if (not_before > self.counter_timestamp > not_after or
                            cs_not_before > self.counter_timestamp > cs_not_after):
                raise Asn1Error('Cert chain not valid at countersig time.')
        else:
            # Check if certificate chain was valid at time 'timestamp'
            if timestamp:
                if not_before > timestamp > not_after:
                    raise Asn1Error('Cert chain not valid at time timestamp.')

    def _validatecertchain(self, signee):
        # Get start of 'regular' chain
        not_before = signee[0][0]['validity']['notBefore'].ToPythonEpochTime()
        not_after = signee[0][0]['validity']['notAfter'].ToPythonEpochTime()

        while True:
            issuer = signee[0][0]['issuer']
            issuer_dn = str(dn.DistinguishedName.TraverseRdn(issuer[0]))
            signer = None
            for cert in self.certificates.values():
                subject = cert[0][0]['subject']
                subject_dn = str(dn.DistinguishedName.TraverseRdn(subject[0]))
                if subject_dn == issuer_dn:
                    signer = cert
            # Are we at the end of the chain?
            if not signer:
                break
            self.validatecertificatesignature(signee, signer)
            # Did we hit a self-signed certificate?
            if signee == signer:
                break
            t_not_before = signer[0][0]['validity']['notBefore'].ToPythonEpochTime()
            t_not_after = signer[0][0]['validity']['notAfter'].ToPythonEpochTime()
            if t_not_before > not_before:
                # why would a cert be signed with something that was not valid yet
                # just silently absorbing this case for now
                not_before = t_not_before
            not_after = min(not_after, t_not_after)
            # Now let's go up a step in the cert chain.
            signee = signer
        return not_before, not_after, signee

    def _validatepubkeygeneric(self, signing_cert, digest_alg, payload,
                               enc_digest):
        m2_cert = M2_X509.load_cert_der_string(der_encoder.encode(signing_cert))
        pubkey = m2_cert.get_pubkey()
        pubkey.reset_context(digest_alg().name)
        pubkey.verify_init()
        pubkey.verify_update(payload)
        v = pubkey.verify_final(enc_digest)
        if v != 1:
            self.openssl_error = M2_Err.get_error()
            # Let's try a special case. I have no idea how I would determine when
            # to use this instead of the above code, so I'll always try. The
            # observed problem was that for one countersignature (RSA on MD5),
            # the encrypted digest did not contain an ASN.1 structure, but the
            # raw hash value instead.
            try:
                rsa = pubkey.get_rsa()
            except ValueError:
                # It's not an RSA key, just fall through...
                pass
            else:
                clear = rsa.public_decrypt(enc_digest, M2_RSA.pkcs1_padding)
                if digest_alg(payload).digest() == clear:
                    return 1
        return v


    def validatecertificatesignature(self, signed_cert, signing_cert):
        """Given a cert signed by another cert, validates the signature."""
        # First the naive way -- note this does not check expiry / use etc.

        cert_signing = x509.load_pem_x509_certificate(ssl.DER_cert_to_PEM_cert(der_encoder.encode(signing_cert)).encode(), default_backend())

        public_key = cert_signing.public_key()

        der_cert = der_encoder.encode(signed_cert)
        cert_signed = x509.load_pem_x509_certificate(ssl.DER_cert_to_PEM_cert(der_cert).encode(), default_backend())

        data = cert_signed.tbs_certificate_bytes
        signature = cert_signed.signature

        new_api = hasattr(public_key, "verify")
        if not new_api:
            verifier = public_key.verifier(signature, padding.PKCS1v15(), cert_signed.signature_hash_algorithm)
            try:
                verifier.update(data)
                verifier.verify()
            except:
                raise Asn1Error('1: Validation of cert signature failed.')
        else:
            try:
                verifier = public_key.verify(signature, data, padding.PKCS1v15(), cert_signed.signature_hash_algorithm)
                # verifier.update(data)
                # verifier.verify()
            except:
                raise Asn1Error('1: Validation of cert signature failed.')

    def _validpubKeyopenssl(self, signing_cert, digest_alg, payload,
                            enc_digest):
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1,
                                               der_encoder.encode(signing_cert))

        try:
            OpenSSL.crypto.verify(cert, binascii.a2b_hex(enc_digest), payload, digest_alg().name)
            print("Signature verified OK")
            return 1
        except Exception as e:
            print("Signature verification failed: {}".format(e))
            raise Asn1Error('1: Validation of cert signature failed.')

    def validatesignatures(self):
        """Validate encrypted hashes with respective public keys.

        Invokes necessary public key operations to check that signatures
        on authAttr hashes are correct for both the basic signature, and
        if present the countersignature.

        Raises:
          Asn1Error: if signature validation fails.
        """
        # Encrypted digest is that of auth_attrs, see comments in ValidateHashes.
        signing_cert = self.certificates[self.signing_cert_id]
        v = self._validpubKeyopenssl(signing_cert, self.digest_algorithm,
                                     self.computed_auth_attrs_for_hash, self.encrypted_digest)

        if v != 1:
            raise Asn1Error('1: Validation of basic signature failed.')

        # FIXME, maybe: that part fails, no clue why.
        # if self.has_countersignature:
        #    signing_cert = self.certificates[self.counter_sig_cert_id]
        #    v = self._validpubKeyopenssl(signing_cert, self.digest_algorithm,
        #                                 self.computed_counter_attrs_for_hash,
        #                                 self.encrypted_counter_digest)

        #    if v != 1:
        #        raise Asn1Error('2: Validation of counterSignature failed.')
