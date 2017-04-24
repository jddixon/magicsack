#!/usr/bin/env python3
# testPuzzle.py

""" Verify that the puzzle presented to the user is valid. """

import time
import unittest

from xlattice.crypto import AES_BLOCK_SIZE
from rnglib import SimpleRNG
from magicsack import generate_key, devise_puzzle, check_puzzle


class TestPuzzle(unittest.TestCase):
    """ Verify that the puzzle presented to the user is valid. """

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    def test_key_func(self):
        """ Test key generation. """

        pass_phrase = 'foo' + self.rng.next_file_name(8)
        salt = bytes(self.rng.some_bytes(16))
        key = generate_key(pass_phrase, salt, count=20)
        self.assertTrue(key is not None)
        self.assertEqual(len(key), 2 * AES_BLOCK_SIZE)

    def test_puzzle(self):
        """ Verify that the generated puzzle works as expected. """

        pass_phrase = 'foo' + self.rng.next_file_name(8)
        count = 20    # default is 1000, but this is a test
        salt = bytes(self.rng.some_bytes(16))

        # we want this the return an immutable 64-byte value
        puzzle = devise_puzzle(pass_phrase, salt, self.rng, count)

        ok_, key = check_puzzle(puzzle, pass_phrase, salt, count)
        self.assertTrue(ok_)
        self.assertFalse(key is None)


if __name__ == '__main__':
    unittest.main()
