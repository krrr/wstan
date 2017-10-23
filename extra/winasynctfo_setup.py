#!/usr/bin/env python3
from setuptools import setup, Extension


setup(name='winasynctfo',
      version=0.2,
      description='TCP Fast Open for asyncio (Windows 10 only)',
      author='krrr',
      url='https://github.com/krrr/wstan/tree/master/extra',
      packages=['winasynctfo'],
      classifiers=[
          'Framework :: AsyncIO',
          'Intended Audience :: Developers',
          'Operating System :: Microsoft :: Windows :: Windows 10',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3 :: Only'],
      ext_modules=[Extension('winasynctfo.overlapped', ['winasynctfo/overlapped.cpp'])])
