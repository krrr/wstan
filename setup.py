#!/usr/bin/env python3
from setuptools import setup, find_packages


setup(name='wstan',
      version='0.4.2',
      description='Tunneling TCP in WebSocket',
      author='krrr',
      author_email='guogaishiwo@gmail.com',
      url='https://github.com/krrr/wstan',
      keywords='proxy tunnel websocket',
      packages=find_packages(),
      classifiers=[
          'Topic :: Internet :: Proxy Servers',
          'Operating System :: OS Independent',
          'License :: OSI Approved :: MIT License',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3.7',
          'Programming Language :: Python :: 3.8',
          'Programming Language :: Python :: 3 :: Only'],
      entry_points={'console_scripts': ['wstan = wstan:main_entry']})
