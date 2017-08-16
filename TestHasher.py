import argparse
import base64
import binascii
import hashlib
import os
import sys
import unittest

from unittest import mock

from pprint import pprint

    
pgm_name = 'TestHasher.py'
pgm_version = '1.0'

arg_parser = argparse.ArgumentParser(prog='%s' % pgm_name, description='SHA256 hash, PBKDF2 hash, and PBKDF2 rehash utility program.')

arg_parser.add_argument('--srcValue', default='abc123', help='source value')
arg_parser.add_argument('--hashRounds', type=int, default=100, help='number of hash rounds')

arg_parser.add_argument('--version', action='version', version='version=%s %s' % (pgm_name, pgm_version))

arg_parser.add_argument('--port', type=int, default=56990)
arg_parser.add_argument('--verbosity', type=int, default=0)

args = None

class TestHasher():

    def main(self,
             cmdline=None):

        if cmdline is not None:
            args = arg_parser.parse_args(cmdline.split())
        else:
            args = arg_parser.parse_args()    
    
        print("Python 3.4+ Hashing");
    
        print ('')
        print ('SHA256 hash of source_value follows')
        print ('===================================')
    
        hashedResult_SHA256, saltValueHex = self.hash_value_via_the_specs_SHA256(args.srcValue, hashRounds=args.hashRounds, isTestMode=True)
    
        print ('')
        print ('PBKDF2 hash of source_value follows')
        print ('===================================')
    
        hashedResult_PBKDF2_1000, saltValueHex = self.hash_via_pbkdf2_hmac(args.srcValue, hashRounds=args.hashRounds, isTestMode=True)
    
        print ('')
        print ('PBKDF2 hash of HASH_SHA_256 result value follows')
        print ('================================================')
    
        hashedResult_REHASH, saltValueHex = self.hash_via_pbkdf2_hmac(hashedResult_SHA256, hashRounds=args.hashRounds, isTestMode=True)
    
        return
    
    
    # ========================================================================
    # Hash a value according to the specifications
    # ========================================================================
    
    def hash_value_via_the_specs_SHA256(self,
                                        srcValue='abc123',
                                        hashRounds=100,
                                        srcEncoding='cp1252',
                                        tgtEncoding='cp1252',
                                        isTestMode=False,
                                        isDebugMode=False):
    
        hashedResult = None
        saltValueHex = None
    
        if hashRounds > 0:
    
            if isDebugMode:
                print('initialValue : %s' % srcValue)
                print('rounds2HashIt: %d' % hashRounds)
    
            # clear and build up saltValue2bHashed variable
            saltValue2bHashed = ''.encode(encoding=srcEncoding)
            bytSrcValue = srcValue.encode(encoding=srcEncoding)
            saltValue2bHashed += bytSrcValue
    
            if isDebugMode:
                print('saltValue2bHashed: %s' % saltValue2bHashed)
    
            # hash the saltValue2bHashed variable
            # and convert it to a hexadecimal string,
            # which will become the salt for
            # the next hashing to be done below
            hash_salt = hashlib.sha256()
            hash_salt.update(saltValue2bHashed)
            salt_value = hash_salt.digest()
            saltValueHex = binascii.b2a_hex(salt_value).decode(srcEncoding)
    
            if isDebugMode:
                print('saltValueHex: %s' % saltValueHex)
    
            # clear and build up value2bHashed variable
            # by concatenating the srcValue with the saltValue
            value2bHashed = ''.encode(encoding=srcEncoding)
            bytSrcValue = (srcValue + saltValueHex).encode(encoding=srcEncoding)
            value2bHashed += bytSrcValue
    
            if isDebugMode:
                print('value2bHashed: %s' % value2bHashed)
    
            # hash the value2bHashed
            # for the number of rounds,
            # decoding the resulting
            # value via base64 encoding
            hash_algo = hashlib.sha256()
            hash_algo.update(value2bHashed)
            # hash the first round
            hash_value = hash_algo.digest()
            # hash the remaining rounds
            for i in range(hashRounds-1):
                hash_value = hashlib.sha256(hash_value).digest()
            # translate the resulting hash into a Base64 string
            hashedResult = base64.b64encode(hash_value).decode(tgtEncoding)
    
            if isDebugMode:
                print('hashedResult: %s' % hashedResult)
    
            if isTestMode:
                print('')
    
            print("hash_value_via_the_specs_SHA256(srcValue='%s', rounds=%d)" % (srcValue, hashRounds))
            print('---------------------------------------------------------------')
            print('initialValue : %s' % srcValue)
            print('saltValueHex : %s' % saltValueHex)
            print('value2bHashed: %s' % value2bHashed.decode(srcEncoding))
            print('rounds2HashIt: %d' % hashRounds)
            print('hashedResult : %s' % hashedResult)
    
        return hashedResult, saltValueHex
    
    
    # =======================================================
    # Re-hash a value according to the specifications
    # =======================================================
    
    def hash_via_pbkdf2_hmac(self,
                             srcValue='abc123',
                             hashAlgorithm = 'sha256',
                             dklen=32,
                             hashRounds=100,
                             srcEncoding='cp1252',
                             tgtEncoding='cp1252',
                             isTestMode=False,
                             isDebugMode=False):
    
        hashedResult = None
        saltValueHex = None
    
        if hashRounds > 0:
    
            bytSrcValue = srcValue.encode(encoding=srcEncoding)
    
            # clear and build up saltValue2bHashed variable
            saltValue2bHashed = ''.encode(encoding=srcEncoding)
            saltValue2bHashed += bytSrcValue
    
            # clear and build up value2bHashed variable
            value2bHashed = ''.encode(encoding=srcEncoding)
            value2bHashed += bytSrcValue
    
            # hash the saltValue2bHashed variable
            # which will become the salt for
            # the pbkdf2_hmac hashing routine
            hash_salt = hashlib.sha256()
            hash_salt.update(saltValue2bHashed)
            salt_value = hash_salt.digest()
            # convert salt value to a hexadecimal string
            saltValueHex = binascii.b2a_hex(salt_value).decode(srcEncoding)
    
            # rehash the value2bHashed via the pbkdf2_hmac algorithm
            pbkdf2_hash_value = hashlib.pbkdf2_hmac(hashAlgorithm, value2bHashed, salt_value, hashRounds, dklen=dklen)
    
            # decode the resulting values using base64 encoding
            saltValue = binascii.b2a_hex(salt_value).decode(srcEncoding)
            hashedResult = base64.b64encode(pbkdf2_hash_value).decode(tgtEncoding)
    
            if isDebugMode:
                print('hashedResult: %s' % hashedResult)
    
            if isTestMode:
                print('')
    
            print("hash_via_pbkdf2_hmac(srcValue='%s', rounds=%d)" % (srcValue, hashRounds))
            print('---------------------------------------------------------------')
            print('initialValue : %s' % srcValue)
            print('saltValueHex : %s' % saltValueHex)
            print('value2bHashed: %s' % value2bHashed.decode(srcEncoding))
            print('rounds2HashIt: %d' % hashRounds)
            print('hashedResult : %s' % hashedResult)
    
        return hashedResult, saltValueHex


# =============================================================================
# unit test(s) of above logic
# =============================================================================

class UnitTests_TestHasher(unittest.TestCase):
    
    testHasher = TestHasher()

    def setUp(self):

        id_text = self.id()
        id_desc = self.shortDescription()
        id_line = '-' * len(id_text)
        id_equl = '=' * len(id_text)

        print('')
        print(id_equl)
        print(id_text)
        if id_desc is not None:
            print(id_desc)
        print(id_line)
        print('')
        
        unittest.mock.patch('sys.argv', ['--srcValue=abc123', '--hashRounds=100'])

        return


    def tearDown(self):
        # instantiated objects disposal
        unittest.TestCase.tearDown(self)
        return

    def test_hash_value_via_the_specs_SHA256_rounds_1(self,
                                                      srcValue='abc123',
                                                      hashRounds=1,
                                                      expectedResult='Pbb2/dJkywFxhuW2O33twGm+Gu67UfoEFupDMUeBnuo='):

        hashedResult, saltValueHex = self.testHasher.hash_value_via_the_specs_SHA256(srcValue=srcValue,
                                                                     hashRounds=hashRounds)
        self.assertEqual(hashedResult, expectedResult)

        return

    def test_hash_value_via_the_specs_SHA256_rounds_10(self,
                                                       srcValue='abc123',
                                                       hashRounds=10,
                                                       expectedResult='hv9yokX8vTpSfKhEmALfChVDyjx5TyOmiAkmSMxy3lQ='):

        hashedResult, saltValueHex = self.testHasher.hash_value_via_the_specs_SHA256(srcValue=srcValue,
                                                                     hashRounds=hashRounds)
        self.assertEqual(hashedResult, expectedResult)

        return

    def test_hash_value_via_the_specs_SHA256_rounds_100(self,
                                                        srcValue='abc123',
                                                        hashRounds=100,
                                                        expectedResult='JRXbc/4pYE8lcz9tjyzntwMtZUUnA6OQTs4V6hpjlRo='):

        hashedResult, saltValueHex = self.testHasher.hash_value_via_the_specs_SHA256(srcValue=srcValue,
                                                                     hashRounds=hashRounds)
        self.assertEqual(hashedResult, expectedResult)

        return

    def test_hash_value_via_the_specs_SHA256_rounds_1000(self,
                                                         srcValue='abc123',
                                                         hashRounds=1000,
                                                         expectedResult='aJDhkskZ9OwP1n1akIoOgReHjm+iFJ0ofPt3CNhvFy8='):

        hashedResult, saltValueHex = self.testHasher.hash_value_via_the_specs_SHA256(srcValue=srcValue,
                                                                     hashRounds=hashRounds)
        self.assertEqual(hashedResult, expectedResult)

        return

    def test_hash_via_pbkdf2_hmac_rounds_1(self,
                                           srcValue='abc123',
                                           hashRounds=1,
                                           expectedResult='OxitRJaFxXKohq/SGhN00+PimSM8ROoObb7LUtuCNsk='):

        hashedResult, saltValueHex = self.testHasher.hash_via_pbkdf2_hmac(srcValue=srcValue,
                                                          hashRounds=hashRounds)
        self.assertEqual(hashedResult, expectedResult)

        return

    def test_hash_via_pbkdf2_hmac_rounds_10(self,
                                            srcValue='abc123',
                                            hashRounds=10,
                                            expectedResult='LErx9BRgGTIgvHBu9+c1XFnHy+pVjSsbLtPA+cjecaA='):

        hashedResult, saltValueHex = self.testHasher.hash_via_pbkdf2_hmac(srcValue=srcValue,
                                                          hashRounds=hashRounds)
        self.assertEqual(hashedResult, expectedResult)

        return

    def test_hash_via_pbkdf2_hmac_rounds_100(self,
                                             srcValue='abc123',
                                             hashRounds=100,
                                             expectedResult='agzFahJTRsm2661hxAMf1hjsPOPNa7PMH7tf6bWNtsg='):

        hashedResult, saltValueHex = self.testHasher.hash_via_pbkdf2_hmac(srcValue=srcValue,
                                                          hashRounds=hashRounds)
        self.assertEqual(hashedResult, expectedResult)

        return

    def test_hash_via_pbkdf2_hmac_rounds_1000(self,
                                              srcValue='abc123',
                                              hashRounds=1000,
                                              expectedResult='qD5Lgzr7JmfEOtic7+qiv2MPUpEUQx1QlG5TsHSFxek='):

        hashedResult, saltValueHex = self.testHasher.hash_via_pbkdf2_hmac(srcValue=srcValue,
                                                          hashRounds=hashRounds)
        self.assertEqual(hashedResult, expectedResult)

        return

    def test_hash_via_rehash_hash_rounds_1(self,
                                           srcValue='abc123',
                                           hashRounds=1,
                                           expectedResult='Fs6SgmSnv8MBUs8oNdmHGDKgUUTc9pDnM4Qh7EDM0X8='):


        hashedResult, saltValueHex = self.testHasher.hash_value_via_the_specs_SHA256(srcValue=srcValue,
                                                                     hashRounds=hashRounds)
        print('')
        hashedResult, saltValueHex = self.testHasher.hash_via_pbkdf2_hmac(srcValue=hashedResult,
                                                          hashRounds=hashRounds)
        self.assertEqual(hashedResult, expectedResult)

        return

    def test_hash_via_rehash_hash_rounds_10(self,
                                            srcValue='abc123',
                                            hashRounds=10,
                                            expectedResult='dxmK0pLC74pyh6suezn0DHysdqhsBE5z3Fbd8tpMUmY='):


        hashedResult, saltValueHex = self.testHasher.hash_value_via_the_specs_SHA256(srcValue=srcValue,
                                                                     hashRounds=hashRounds)
        print('')
        hashedResult, saltValueHex = self.testHasher.hash_via_pbkdf2_hmac(srcValue=hashedResult,
                                                          hashRounds=hashRounds)
        self.assertEqual(hashedResult, expectedResult)

        return

    def test_hash_via_rehash_hash_rounds_100(self,
                                             srcValue='abc123',
                                             hashRounds=100,
                                             expectedResult='TtBe4DXKox1fiwT6dF539g67n9Or3XbrZ8mlaLdrR5Q='):


        hashedResult, saltValueHex = self.testHasher.hash_value_via_the_specs_SHA256(srcValue=srcValue,
                                                                     hashRounds=hashRounds)
        print('')
        hashedResult, saltValueHex = self.testHasher.hash_via_pbkdf2_hmac(srcValue=hashedResult,
                                                          hashRounds=hashRounds)
        self.assertEqual(hashedResult, expectedResult)

        return

    def test_hash_via_rehash_hash_rounds_1000(self,
                                              srcValue='abc123',
                                              hashRounds=1000,
                                              expectedResult='loT7qcXPc2wRuAbv53oUm5yvuwDNx5qBhmEhdF60LII='):


        hashedResult, saltValueHex = self.testHasher.hash_value_via_the_specs_SHA256(srcValue=srcValue,
                                                                     hashRounds=hashRounds)
        print('')
        hashedResult, saltValueHex = self.testHasher.hash_via_pbkdf2_hmac(srcValue=hashedResult,
                                                          hashRounds=hashRounds)
        self.assertEqual(hashedResult, expectedResult)

        return


# =============================================================================
# execute the "main" method
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    TestHasher().main()
