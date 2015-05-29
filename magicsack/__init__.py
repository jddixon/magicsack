# magicsack/__init__.py

__all__ = [ '__version__', '__version_date__',
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
