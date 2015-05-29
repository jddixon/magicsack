#!/usr/bin/python3

# testPuzzle.py

import os, time, unittest

from xlattice.crypto import AES_BLOCK_SIZE
from rnglib         import SimpleRNG
from magicsack      import *

class TestPuzzle (unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG( time.time() )
    def tearDown(self):
        pass

    # utility functions #############################################
    
    # actual unit tests #############################################
   
    def testKeyFunc(self):
        passPhrase  = 'foo' + self.rng.nextFileName(8)
        salt        = bytes(self.rng.someBytes(16))
        key         = generateKey(passPhrase, salt, count=20)
        self.assertTrue(key is not None)
        self.assertEqual(len(key), 2 * AES_BLOCK_SIZE)

    def testPuzzle (self):
        passPhrase  = 'foo' + self.rng.nextFileName(8)
        count       = 20    # default is 1000, but this is a test
        salt        = bytes(self.rng.someBytes(16))

        # we want this the return an immutable 64-byte value
        puzzle = devisePuzzle(passPhrase, salt, self.rng, count)
        
        self.assertTrue(checkPuzzle(puzzle, passPhrase, salt, count))

if __name__ == '__main__':
    unittest.main()
