#!/usr/bin/env python3
import sys
from setuptools import setup, Extension

ext = Extension('asynctfo.overlapped', ['asynctfo/overlapped.cpp'])

setup(name='asynctfo',
      version=0.2,
      description='TCP Fast Open for asyncio',
      author='krrr',
      url='https://github.com/krrr/wstan/tree/master/extra',
      packages=['asynctfo'],
      classifiers=[
          'Framework :: AsyncIO',
          'Intended Audience :: Developers',
          'Operating System :: Microsoft :: Windows :: Windows 10',
          'Operating System :: POSIX :: Linux',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3 :: Only'],
      ext_modules=[ext] if sys.platform == 'win32' else None)
