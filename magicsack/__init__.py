# magicsack/__in(it__.py

import binascii

from pbkdf2         import PBKDF2       # note name of package is u/c
from Crypto.Cipher  import AES
from Crypto.Hash      import SHA       
from Crypto.PublicKey import RSA

from xlattice.crypto  import (
    AES_BLOCK_SIZE, addPKCS7Padding, stripPKCS7Padding)

__all__ = [ '__version__', '__version_date__',
            'generateKey', 'devisePuzzle', 'checkPuzzle',
          ]

__version__      = '0.2.8'
__version_date__ = '2015-05-28'

# OTHER EXPORTED CONSTANTS

class Config(object):

    def __init__(self, salt, uDir):
        self._salt  = salt
        self._uDir  = uDir

    @property 
    def salt(self):         return self._salt

    @property
    def uDir(self):         return self._uDir


def generateKey(passPhrase, salt, count=1000):
    """ 
    passPhrase is a string which may not be empty.  salt is a 
    byte array, conventionally either 8 or 16 bytes.  The
    key returned is a 256-bit value.
    """
    if not passPhrase or passPhrase == '':
        raise RuntimeError("empty passPhrase")
    if not salt or len(salt)==0:
        raise RuntimeError("you must supply a salt")
    # it is also possible to set the hash function used; it defaults 
    # to HMAC-SHA1
    return PBKDF2(passPhrase, salt, iterations=count).read(32)

def devisePuzzle(passPhrase, salt, rng, count=1000):
    key     = generateKey(passPhrase, salt, count)
    junk    = rng.someBytes(2 * AES_BLOCK_SIZE)
    iv      = bytes(junk[:AES_BLOCK_SIZE])
    junk0   = junk[AES_BLOCK_SIZE   : AES_BLOCK_SIZE+8]
    junk2   = junk[AES_BLOCK_SIZE+8 : ]

    data    = junk0 + salt + junk2
    padded  = bytes(addPKCS7Padding(data, AES_BLOCK_SIZE))
    cipher  = AES.new(key, AES.MODE_CBC, iv)
    puzzle  = bytes(iv + cipher.encrypt(padded))

    return puzzle

def checkPuzzle(puzzle, passPhrase, salt, count=1000):
    key     = generateKey(passPhrase, salt, count)
    iv      = puzzle[:AES_BLOCK_SIZE]
    cipher  = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(puzzle[AES_BLOCK_SIZE:])
    data    = stripPKCS7Padding(decrypted, AES_BLOCK_SIZE)
    soln    = bytes(data[8:8+AES_BLOCK_SIZE])

    return soln == salt
