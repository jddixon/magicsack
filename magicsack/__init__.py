# magicsack/__init__.py

__all__ = [ '__version__', '__version_date__',
            'AES_BLOCK_SIZE',
            'pkcs7Padding',
            'addPKCS7Padding',
            'stripPKCS7Padding',
          ]

__version__      = '0.2.2'
__version_date__ = '2015-05-09'

# OTHER EXPORTED CONSTANTS

AES_BLOCK_SIZE  = 16


# CRYPTO FUNCTIONS (should be in separate package) ##################

class CryptoException(Exception):
    pass

def pkcs7Padding(data, blockSize):
    if blockSize < 1:
        raise CryptoException("impossible block size")
    if not data:
        length = 0
    else:
        length = len(data)

    # we want from 1 to blockSize bytes of padding
    nBlocks = (length + blockSize - 1) / blockSize
    rem = nBlocks * blockSize - length
    if rem == 0:
        rem = blockSize
    padding = bytearray(rem)    # that many null bytes
    for i in range(rem):
        padding[i] = rem        # padding bytes set to length of padding
    return padding


def addPKCS7Padding(data, blockSize):
    if blockSize <= 1 :
        raise CryptoException("impossible block size")
    else :
        padding = pkcs7Padding(data, blockSize)
        if not data :
            out = padding
        else :
            out = data + padding
    return out


# The data passed is presumed to have PKCS7 padding.  If possible, return
# a copy of the data without the padding.  Return an error if the padding
# is incorrect.

def stripPKCS7Padding(data, blockSize):
    if blockSize <= 1 :
        raise CryptoException("impossible block size")
    elif not data:
        raise CryptoException("cannot strip padding from empty data")
    lenData = len(data)
    if lenData < blockSize :
        raise CryptoException("data too short to have any padding")
    else :
        # examine the very last byte: it must be padding and must
        # contain the number of padding bytes added
        lenPadding = data[lenData-1]
        if lenPadding < 1 or lenData < lenPadding :
            raise CryptoException("incorrect PKCS7 padding")
        else :
            out = data[:lenData-lenPadding]
    return out

