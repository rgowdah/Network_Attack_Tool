#!/usr/bin/python
__author__ = 'kilroy'
#  (c) 2014, WasHere Consulting, Inc.
#  Written for Infinite Skills

import http.client as http_lib

host = "www.google.com"

req = http_lib.HTTPConnection(host)
req.putrequest("HEAD", "/")
req.putheader("Host", host)
req.endheaders()
req.send("")

resp= req.getresponse()
print("Status: ", resp.getcode())
