from setuptools import setup, find_packages
import wstan


setup(name='wstan',
      author='krrr',
      author_email='guogaishiwo@gmail.com',
      version=wstan.__version__,
      description='Tunneling TCP connection in WebSocket',
      url='https://github.com/krrr/wstan',
      packages=find_packages(),
      requires=['cryptography'],
      classifiers=[
          'Topic :: Internet :: Proxy Servers',
          'Intended Audience :: Developers',
          'Programming Language :: Python :: 3.3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3 :: Only'],
      entry_points={'console_scripts': ['wstan = wstan:main_entry']})
