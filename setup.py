from setuptools import setup
import wstan


setup(name='wstan',
      author=wstan.__author__,
      version=wstan.__version__,
      description='',
      url='https://krrr.github.io',
      packages=['wstan'],
      requires=['autobahn', 'cryptography'],
      entry_points={'console_scripts': ['wstan = wstan:main_entry']})
