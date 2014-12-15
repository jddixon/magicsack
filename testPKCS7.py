#!/usr/bin/python3

# magicsack/testPKCS7.py

import base64, hashlib, os, time, unittest

from rnglib         import SimpleRNG
from magicsack      import *

class TestPKCS7Padding (unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG( time.time() )
    def tearDown(self):
        pass

    # utility functions #############################################
    
    # actual unit tests #############################################
    
    def testPadding (self):

        seven = bytearray(7)
        self.rng.nextBytes(seven)

        fifteen = bytearray(15)
        self.rng.nextBytes(fifteen)

        sixteen = bytearray(16)
        self.rng.nextBytes(sixteen)

        seventeen = bytearray(17)
        self.rng.nextBytes(seventeen)

        padding = pkcs7Padding(seven, AES_BLOCK_SIZE)
        self.assertEquals(len(padding), AES_BLOCK_SIZE-7)
        self.assertEquals(padding[0], AES_BLOCK_SIZE-7)

        padding = pkcs7Padding(fifteen, AES_BLOCK_SIZE)
        self.assertEquals(len(padding), AES_BLOCK_SIZE-15)
        self.assertEquals(padding[0], AES_BLOCK_SIZE-15)

        padding = pkcs7Padding(sixteen, AES_BLOCK_SIZE)
        self.assertEquals(len(padding), AES_BLOCK_SIZE)
        self.assertEquals(padding[0], 16)

        padding = pkcs7Padding(seventeen, AES_BLOCK_SIZE)
        expectedLen = 2*AES_BLOCK_SIZE - 17
        self.assertEquals(len(padding), expectedLen)
        self.assertEquals(padding[0], expectedLen)

        paddedSeven = addPKCS7Padding(seven, AES_BLOCK_SIZE)
        unpaddedSeven = stripPKCS7Padding(paddedSeven, AES_BLOCK_SIZE)
        self.assertEquals(seven, unpaddedSeven)

        paddedFifteen = addPKCS7Padding(fifteen, AES_BLOCK_SIZE)
        unpaddedFifteen = stripPKCS7Padding(paddedFifteen, AES_BLOCK_SIZE)
        self.assertEquals(fifteen, unpaddedFifteen)

        paddedSixteen = addPKCS7Padding(sixteen, AES_BLOCK_SIZE)
        unpaddedSixteen = stripPKCS7Padding(paddedSixteen, AES_BLOCK_SIZE)
        self.assertEquals(sixteen, unpaddedSixteen)

        paddedSeventeen = addPKCS7Padding(seventeen, AES_BLOCK_SIZE)
        unpaddedSeventeen = stripPKCS7Padding(paddedSeventeen, AES_BLOCK_SIZE)
        self.assertEquals(seventeen, unpaddedSeventeen)


if __name__ == '__main__':
    unittest.main()

