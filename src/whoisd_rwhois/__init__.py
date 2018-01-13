# -*- coding: utf-8 -*-
from pkg_resources import get_distribution, DistributionNotFound

try:
    __version__ = get_distribution(__name__).version
except DistributionNotFound:
    __version__ = 'unknown'


__version__ = '0.0.2'
__url__ = 'https://github.com/teadur/whoisd-rwhois'
__author__ = 'Georg Kahest'
__email__ = 'georg@gj.ee'
