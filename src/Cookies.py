#!/usr/bin/python
__author__ = 'kilroy'
#  (c) 2014, WasHere Consulting, Inc.
#  Written for Infinite Skills

import urllib.request

url = "https://www.google.com"
request = urllib.request.Request(url)
resp = urllib.request.urlopen(request)
cookies = resp.info()['Set-Cookie']
content = resp.read()
resp.close()
print (cookies, content)