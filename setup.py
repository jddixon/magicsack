#!/usr/bin/python3
# magicsack/setup.py

""" Setuptools project configuration for magicsack. """

from os.path import exists
from setuptools import setup

LONG_DESC = None
if exists('README.md'):
    with open('README.md', 'r') as file:
        LONG_DESC = file.read()

setup(name='magicsack',
      version='0.4.11',
      author='Jim Dixon',
      author_email='jddixon@gmail.com',
      long_description=LONG_DESC,
      packages=['magicsack'],
      package_dir={'': 'src'},
      py_modules=[],
      include_package_data=False,
      zip_safe=False,
      scripts=['src/magicSack'],
      description='generator for magicsack projects',
      url='https://jddixon.github.io/magicsack',
      classifiers=[
          'Development Status :: 2 - Pre-Alpha',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Natural Language :: English',
          'Programming Language :: Python 2.7',
          'Programming Language :: Python 3.3',
          'Programming Language :: Python 3.4',
          'Programming Language :: Python 3.5',
          'Programming Language :: Python 3.6',
          'Programming Language :: Python 3.7',
          'Topic :: Software Development :: Libraries :: Python Modules',
      ],)
