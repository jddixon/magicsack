#!/usr/bin/python3

# magicsack/setup.py

import re
from distutils.core import setup
__version__ = re.search("__version__\s*=\s*'(.*)'",
                        open('magicsack/__init__.py').read()).group(1)

# see http://docs.python.org/distutils/setupscript.html

setup(name='magicsack',
      version=__version__,
      author='Jim Dixon',
      author_email='jddixon@gmail.com',
      py_modules=[],
      packages=['magicsack'],
      # following could be in scripts/ subdir
      scripts=['magicSack', ],
      # MISSING description
      classifiers=[
          'Development Status :: 2 - Pre-Alpha',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Natural Language :: English',
          'Programming Language :: Python 3',
      ],
      )
