"""Very hacky module that extended asyncio to support TCP Fast Open"""
import sys

if sys.platform == 'win32':
    from .win import TfoEventLoop
else:
    from .linux import TfoEventLoop
