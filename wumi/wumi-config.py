#!/usr/local/bin/python2.5

from mailbox import Maildir
import email
import gdbm
import getopt
import os
import os.path
import sys

class WVSDB: # wumi valid sender database

    def __init__ (self):
        self.filename = "/tmp/wumi-validsender/%s.gdbm" % os.getlogin ()
        self.db = gdbm.open (self.filename, "cuf")
        if not self.db.has_key ("active"):
            self.set_inactive ()
        if not self.db.has_key ("bouncetext"):
            self.db ["bouncetext"] = "User has not set any bounce text"
        if not self.db.has_key ("never"):
            self.db ["never"] = ""
	self.do_never ()

    def do_never (self):
	never = set (self.db ["never"].split (","))
	if "" in never: never.remove ("")
	self._never = never
	for addr in never:
	    if addr in self.db.keys ():
		print "DELETING %s (is set in never)." % addr
		del (self.db [addr])
     
    def close (self):
        self.db.sync ()
        self.db.close ()

    def wipe (self):
        if raw_input ("REALLY SURE (Y)? ") != "Y":
            print "aborting ... "
            sys.exit (1)
        ks = self.db.keys ()
        ks.remove ("bouncetext")
        for k in ks:
            del (self.db [k])

    def settext (self, filename):
        self.db ["bouncetext"] = file (filename).read ()
        
    def __str__ (self):
        if self.is_active (): act = "active"
        else: act = "inactive"    
        s = "\nWVSDB %s is %s\n" % (self.filename, act)
        if not self.db.has_key (''):
            s += "WARNING: you do not accept bounces\n"
        s += "\nBounce Message is:\n"
        s += '"' + self.db ["bouncetext"] + '"\n'
	s += "Never add: %s\n" % (self._never)
        s += "\n%d Addresses in Database:\n" % (len (self.db.keys ()) - 2)
        l = self.db.keys ()
        l.remove ("active")
        l.remove ("bouncetext")
        l.remove ("never")
        l.sort ()
        for m in l:
            s += "%s\n" % m
        return s    
        
    def msg_addrs (self, msg):
        msg = email.message_from_string (str (msg))
        mfrom = map (lambda x:x[1].lower (), email.utils.getaddresses (msg.get_all ("from", [])))
        retpa = map (lambda x:x[1].lower (), email.utils.getaddresses (msg.get_all ("return-path", [])))
        cc    = map (lambda x:x[1].lower (), email.utils.getaddresses (msg.get_all ("cc", [])))
        to    = map (lambda x:x[1].lower (), email.utils.getaddresses (msg.get_all ("to", [])))
        return mfrom, retpa, cc, to
        
    def update (self, maildir, allcc = False, fromaddr = None):
        """updates Database
        allcc: add all from: and cc: addresses from all mails
        fromaddr: if set, add cc: only from this sender"""
        maildir = Maildir (maildir)
        if fromaddr: fromaddr = fromaddr.lower ()
        for msg in maildir:
            mfrom, retpa, cc, to = self.msg_addrs (msg)
            # mfrom header is set and it is identical to the give address
            if allcc or (mfrom and fromaddr and mfrom [0] == fromaddr):
                self._updatel (mfrom)
                self._updatel (retpa)
                self._updatel (to)
                self._updatel (cc)
            # add from: and return-path: in any case    
            elif mfrom or retpa:
                self._updatel (mfrom)
                self._updatel (retpa)
            else:
                pass

    def _updatel (self, l):
        for address in l:
            if not self.db.has_key (address) and address not in self._never:
                print "adding: <%s>" % address
                self.db [address] = ""

    def add (self, address):
        if self.db.has_key (address):
            print "Address %s already in database!" % address
	elif address in self._never:
	    print "You never want to add %s to the database" % address
        else:    
            self.db [address.lower ()] = ""

    def is_active (self):
        if self.db ["active"]: return True
        return False

    def set_active (self):
        self.db ["active"] = "1"

    def set_inactive (self):
        self.db ["active"] = ""

    def never (self, l):
	self.db ["never"] = l.lower ()
	self.do_never ()

    def delete (self, address, maildir = False):
        if not maildir:
            a = address.lower ()
            if self.db.has_key (a):
                del self.db [a]
            else:
                print "Warning: %s is not in database" % a
        else:
            maildir = Maildir (address)
            for msg in maildir:
                mfrom, retpa, cc, to = self.msg_addrs (msg)
                if not retpa: continue
                for address in retpa:
                    address = address.lower ()
                    if self.db.has_key (address):
                        print "deleting: <%s>" % address
                        del (self.db [address])



def usage ():
    print """
%s configure the wumi validfrom plugin database in your home

Usage: %s command

commands:
    -a --active   ... sets the database in active mode
    -i --inactive ... sets the database inactive
    -l --list     ... list addresses in database
    -w --wipe     ... remove all addresses from database
    -h --help     ... show this help message
    -n --newaddr <address>    ... add address (@domain.dom for whole domain)
    -N --never <addr,addr,..> ... never add this address (e.g. your own address)
    -d --delete <address>     ... delete this address from database
    -D --Delete <maildirpath> ... delete adresses from From: Headers of theses Mails
    -t --settext <file>       ... read file and set text for bounces 
    -U --Update <maildirpath> ... receive mail from all addresses of headers in Maildir
                                  (not recommended)
    -u --update <from-addr,maildirpath> ... add all recepients in mails from this address
""" % (sys.argv [0], sys.argv [0])

########
# MAIN #
########
sys.argv [0] = os.path.split (sys.argv [0])[-1]
try:
    opts, args = getopt.getopt (sys.argv[1:], "ailwhn:N:d:D:t:u:U:", ["active", "inactive", \
            "list", "wipe", "help", "newaddr=", "never=", "delete=", "Delete=", "settext=", "update=", \
            "Update="])

except getopt.GetoptError, err:
    print str(err)
    usage()
    sys.exit(2)

if len (opts) != 1:
    print "ERROR: %s takes exactly one command" % sys.argv [0]
    usage ()
    sys.exit (2)

db = WVSDB ()

for o, a in opts:
    if o in ("-a", "--active"): db.set_active ()
    elif o in ("-i", "--inactive"): db.set_inactive ()
    elif o in ("-l", "--list"): print db
    elif o in ("-w", "--wipe"): db.wipe ()
    elif o in ("-h", "--help"):
        usage()
        sys.exit()
    elif o in ("-l", "--list"): print db
    elif o in ("-n", "--newaddr"): db.add (a)
    elif o in ("-N", "--never"): db.never (a)
    elif o in ("-d", "--delete"): db.delete (a)
    elif o in ("-D", "--Delete"): db.delete (a, maildir = True)
    elif o in ("-t", "--settext"): db.settext (a)
    elif o in ("-U", "--Update"): db.update (a, allcc = True)
    elif o in ("-u", "--update"):
        fr, md = a.split (",")
        db.update (md, fromaddr = fr)
    else:
        print "Program Error: opt %s" % o
        sys.exit (2)

db.close ()        
