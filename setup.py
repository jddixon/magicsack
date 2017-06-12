#!/usr/bin/python3
# magicsack/setup.py

""" Set up distutils for the magicSack """

import re
from distutils.core import setup
__version__ = re.search(r"__version__\s*=\s*'(.*)'",
                        open('src/magicsack/__init__.py').read()).group(1)

# see http://docs.python.org/distutils/setupscript.html

setup(name='magicsack',
      version=__version__,
      author='Jim Dixon',
      author_email='jddixon@gmail.com',
      py_modules=[],
      packages=['src/magicsack'],
      # following could be in scripts/ subdir
      scripts=['src/magicSack', ],
      description='a place for secret things',
      url='https://jddixon.github.io/magicsack',
      classifiers=[
          'Development Status :: 2 - Pre-Alpha',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Natural Language :: English',
          'Programming Language :: Python 3',
      ])
