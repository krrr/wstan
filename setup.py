from setuptools import setup, find_packages
import wstan


setup(name='wstan',
      author=wstan.__author__,
      version=wstan.__version__,
      description='Tunneling TCP connection in WebSocket',
      url='https://krrr.github.io',
      packages=find_packages(),
      requires=['cryptography'],
      entry_points={'console_scripts': ['wstan = wstan:main_entry']})
