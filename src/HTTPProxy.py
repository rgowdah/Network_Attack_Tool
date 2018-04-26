#!/usr/bin/python
__author__ = 'kilroy'
#  (c) 2014, WasHere Consulting, Inc.
#  Written for Infinite Skills

import urllib.request

proxy = urllib.request.ProxyHandler({'http': '127.0.0.1:8080'})
opener = urllib.request.build_opener(proxy)
urllib.request.install_opener(opener)
handle = urllib.request.urlopen('http://python.org/')

print(handle.read())

