#!/usr/bin/python
__author__ = 'kilroy'
#  (c) 2014, WasHere Consulting, Inc.
#  Written for Infinite Skills

from HTMLParser import HTMLParser
import urllib.request

class myParser(HTMLParser):
    def handle_starttag(self, tag, attrs):
        if (tag == "a"):
            for a in attrs:
                if (a[0] == 'href'):
                    link = a[1]
                    if (link.find('http') >= 0):
                        print(link)
                        newParse = myParser()
                        newParse.feed(link)


url = "http://www.infiniteskills.com/"
request = urllib.request.Request(url)
handle = urllib.request.urlopen(request)
parser = myParser()
parser.feed(handle.read())

