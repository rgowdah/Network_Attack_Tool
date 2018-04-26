#!/usr/bin/python
__author__ = 'kilroy'
#  (c) 2014, WasHere Consulting, Inc.
#  Written for Infinite Skills

import urllib.parse
import urllib.request

url = "http://172.30.42.127/test.php"
data = {'txtName' : 'Ric', 'txtAge' : '19', 'btnSubmit' : 'Submit'}
params = urllib.parse.urlencode(data).encode("utf-8")
req = urllib.request.Request(url, data=params)
opener = urllib.request.build_opener()
response = opener.open(req)
print(response)
