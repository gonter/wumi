#!/usr/bin/env python

import string
import sys
import socket

class Blacklist:

    def __init__ (self, cfparser, name, header):

        self.name         = name
        self.header       = "%s-%s" % (header, name)
        self.cgiurl       = cfparser.get (name, "showcgi")
        self.domain       = cfparser.get (name, "domain")
        self.add_x_header = cfparser.getboolean (name, "add_x_header")
        self.blockmail    = cfparser.getboolean (name, "blockmail")

    def islisted (self, ip):
    
        i = ip.split (".")
        i.reverse ()
        rip = string.join (i, ".")
        i = "%s.%s" % (rip, self.domain)

        try:
            socket.gethostbyname (i)
            islisted = True

        # except socket.gaierror:
        except:
            islisted = False

        return islisted
        
    def smtpmsg (self, ip):
        return "553", "5.3.0", "%s%s" % (self.cgiurl, ip)

    def getheader (self, ip):
        return self.header, "listed: %s%s" % (self.cgiurl, ip)

    def __repr__ (self):
        return "<blacklist object: %s>" % self.domain

