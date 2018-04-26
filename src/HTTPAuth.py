#!/usr/bin/python
__author__ = 'kilroy'
#  (c) 2014, WasHere Consulting, Inc.
#  Written for Infinite Skills

import http.client as http_lib
import base64

h = "172.217.11.7"
u = "ric"
p = "P4ssw0rd"

authToken = base64.encodestring(('%s:%s' % (u,p)).encode()).decode().replace('\n', '')
print(authToken)

req = http_lib.HTTPConnection(h)
req.putrequest("GET", "/index.html")
req.putheader("Host", h)
req.putheader("Authorization", "Basic %s" % authToken)
req.endheaders()
req.send("")

resp = req.getresponse()
print("Response: ", resp.status)
