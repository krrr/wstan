#!/usr/bin/env python3
from setuptools import setup, find_packages
import wstan


setup(name='wstan',
      version=wstan.__version__,
      description='Tunneling TCP in WebSocket',
      author='krrr',
      author_email='guogaishiwo@gmail.com',
      url='https://github.com/krrr/wstan',
      license='MIT',
      keywords='proxy tunnel websocket',
      packages=find_packages(),
      install_requires=['cryptography'],
      extras_require={'advanced_web_log_viewer': ['jinja2'],
                      'win10_tcp_fast_open': ['asynctfo']},
      classifiers=[
          'Topic :: Internet :: Proxy Servers',
          'Operating System :: OS Independent',
          'License :: OSI Approved :: MIT License',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3 :: Only'],
      entry_points={'console_scripts': ['wstan = wstan:main_entry']})
