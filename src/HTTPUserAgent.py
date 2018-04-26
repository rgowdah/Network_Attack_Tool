#!/usr/bin/python
__author__ = 'kilroy'
#  (c) 2014, WasHere Consulting, Inc.
#  Written for Infinite Skills

import http.client as http_lib

h = "www.infiniteskills.com"

req = http_lib.HTTPConnection(h)
req.putrequest("GET", "/")
req.putheader("Host", h)
req.putheader("User-Agent", "Garbage browser: 5.6")
req.putheader("My-Header", "My value")
req.endheaders()
req.send("")

resp = req.getresponse()
print("Response: ", resp.reason)

