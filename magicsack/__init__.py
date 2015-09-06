# magicsack/__in(it__.py

import binascii, hashlib, os

from pbkdf2             import PBKDF2       # note name of package is u/c
from Crypto.Cipher      import AES
from Crypto.Hash        import SHA       
from Crypto.PublicKey   import RSA

from buildList          import BuildList
from nlhtree            import NLHLeaf
from xlattice           import u, SHA1_BIN_NONE, SHA2_BIN_NONE
from xlattice.crypto    import (
    AES_BLOCK_SIZE, addPKCS7Padding, stripPKCS7Padding)

__all__ = [ '__version__', '__version_date__',
            'generateKey', 'devisePuzzle', 'checkPuzzle',
            'makeNamedValueLeaf',
            'writeBuildList',
          ]

__version__      = '0.2.12'
__version_date__ = '2015-09-06'

# OTHER EXPORTED CONSTANTS

class Config(object):

    def __init__(self, salt, uDir):
        self._salt  = salt
        self._uDir  = uDir

    @property 
    def salt(self):         return self._salt

    @property
    def uDir(self):         return self._uDir

class MagicSackError(RuntimeError): 
    pass

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
    
    # DEBUG
    #print("devisePuzzle:")
    #print("  key       %s" % binascii.b2a_hex(key))
    #print("  iv        %s" % binascii.b2a_hex(iv))
    #print("  salt      %s" % binascii.b2a_hex(salt))
    #print("  padded    %s" % binascii.b2a_hex(padded))
    # END
    
    cipher  = AES.new(key, AES.MODE_CBC, iv)
    puzzle  = bytes(iv + cipher.encrypt(padded))

    return puzzle

def checkPuzzle(puzzle, passPhrase, salt, count=1000):
    """
    Determine the key then decipher the puzzle, verifying that
    the copy of the salt embedded in the puzzle is the same as
    the salt from the config file.  Return whether verification
    succeeded.
    """
    key     = generateKey(passPhrase, salt, count)

    iv      = puzzle[:AES_BLOCK_SIZE]
    cipher  = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(puzzle[AES_BLOCK_SIZE:])
    # DEBUG
    #print("checkPuzzle:")
    #print("  key       %s" % binascii.b2a_hex(key))
    #print("  iv        %s" % binascii.b2a_hex(iv))
    #print("  salt      %s" % binascii.b2a_hex(salt))
    #print("  decrypted %s" % binascii.b2a_hex(decrypted))
    # END
    data    = stripPKCS7Padding(decrypted, AES_BLOCK_SIZE)
    soln    = bytes(data[8:8+AES_BLOCK_SIZE])

    return soln == salt, key


# ACTIONS -----------------------------------------------------------
def insertNamedValue(globals, name, data):
    """
    Pad and encrypt the data, writing the encrypted value into uDir.
    If successful, return an NLHLeaf.
    """
    key       = globals.key
    rng       = globals.rng
    uDir      = globals.uDir
    usingSHA1 = globals.usingSHA1

    padded    = addPKCS7Padding(data, AES_BLOCK_SIZE)
    iv        = bytes(rng.someBytes(AES_BLOCK_SIZE))
    cipher    = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded)

    # hash and encrypt the data ---------------------------
    if usingSHA1:
        sha = hashlib.sha1()
    else:
        sha = hashlib.sha256()
    sha.update(encrypted)
    binHash = sha.digest()
    hexHash = binascii.b2a_hex(binHash).decode('utf-8')

    # DEBUG
    print("len(encrypted) = %d" % len(encrypted))
    print("len(hexHash)   = %d" % len(hexHash))
    print("uDir           = %s" % uDir)
    # END

    # add the encrypted data to uDir -----------------------
    if usingSHA1:
        length, hash = u.putData1(encrypted, uDir, hexHash)
    else:
        length, hash = u.putData2(encrypted, uDir, hexHash)
    if hexHash != hash:
        raise MagicSackError(
            "INTERNAL ERROR: content key was '%s' but u returned '%s'" % (
                hash, hexHash))
    if len(encrypted) != length:
        raise MagicSackError("length encrypted %d but %d bytes written" % (
                len(encrypted), length))
    
    return binHash

def makeNamedValueLeaf(globals, name, data):
    
    hash = insertNamedValue(globals, name, data)
    return NLHLeaf(name, hash)

def addAFile(globals, pathToFile, listPath=None):
    """
    Add the contents of a single file to the nlhTree and the content-keyed 
    store.  The file is located at 'pathToFile'.  Its name in the NLHTree
    will be 'listPath'.  If listPath is not set, it defaults to pathToFile.

    Return a possibly empty status string.
    """
    rng         = globals.rng
    tree        = globals.tree
    uDir        = globals.uDir
    usingSHA1   = globals.usingSHA1
    status      = ''

    if not os.path.exists(pathToFile):
        status = 'file not found: %s' % pathToFile
   
    if not status:

        # -----------------------------------------------------------
        # XXX CRITICALLY THIS ASSUMES that the file can be read into memory
        # as a single operation; chunking is not required.
        # -----------------------------------------------------------
       
        # read, pad, and encrypt the file -----------------

        with open(pathToFile, 'rb') as f:
            data = f.read()
        padded = addPKCS7Padding(data, AES_BLOCK_SIZE)
        iv = rng.someBytes(AES_BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(padded)

        # hash the file and add it to uDir ----------------
        if usingSHA1:
            sha = hashlib.sha1()
        else:
            sha = hashlib.sha256()
        sha.update(encrypted)
        hexHash = sha.hexdigest()

        if usingSHA1:
            length, hash = u.putData1(encrypted, uDir, hexHash)
        else:
            length, hash = u.putData2(encrypted, uDir, hexHash)
        if hash != key:
            status = "INTERNAL ERROR: content key was '%s' but u returned '%s'" % (hexHash, hash)
        if not status and len(encrypted) != length:
            status = "length encrypted %d but %d bytes written" % (
                    len(encrypted), length)

    if not status:
        # add the file to the NLHTree ---------------------
        if not listPath:
            listPath = pathToFile
        leaf = NLHLeaf(listPath, hexHash)
        tree.insert(leaf)
    
    return status

# BUILD LIST --------------------------------------------------------

def writeBuildList(globals):
    key       = globals.key
    magicDir  = globals.magicDir
    rng       = globals.rng
    sk        = globals.sk
    skPriv    = globals.skPriv
    title     = globals.title
    tree      = globals.tree
    buildList = BuildList(title, sk, tree)

    # sign build list, encrypt, write to disk -------------
    buildList.sign(skPriv)
    s         = buildList.__str__().encode('utf-8')
    padded    = addPKCS7Padding(s, AES_BLOCK_SIZE)
    iv        = bytes(rng.someBytes(AES_BLOCK_SIZE))
    cipher    = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded)
    pathToBL  = os.path.join(magicDir, 'b')
    with open(pathToBL, 'wb') as f:
        f.write(encrypted)

def readBuildList(globals):
    """
    """
    key       = globals.key
    magicDir  = globals.magicDir
    rng       = globals.rng
    uDir      = globals.uDir
    usingSHA1 = globals.usingSHA1

    pathToBL  = os.path.join(magicDir, 'b')
    with open(pathToBL, 'rb') as f:
        data = f.read()
    iv = data[:AES_BLOCK_SIZE]
    ciphertext = data[AES_BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    s = stripPKCS7Padding(plaintext)
    buildList = BuildList.parse(s, usingSHA1)
    if not buildList.verify():
        raise MagicSackError("could not verify digital signature on BuildList")

    globals.timestamp   = buildList.timestamp
    globals.title       = buildList.title
    globals.tree        = buildList.tree

    # retrieve __ckPriv__ and __skPriv__ hashes from the BuildList, and
    # use these to extract their binary values from uDir
    # Retrieve any top-level leaf nodes whose names begin with double
    # underscores ('__').  Regard these as reserved names.  For any
    # such keys, add the key/value combination to globals, where the
    # value is a hexHash.

