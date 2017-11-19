#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# $Id: wumi.py,v 1.34 2008/07/12 19:36:45 schurlix Exp $

# import sys / site / own-ext / proj
import StringIO
import gdbm
import md5
import os
import os.path
import sys
import syslog
import tempfile
import types
import traceback
import zipfile
import zlib
from email import Errors
from email import Message
import email
from threading import Lock
from spambayes import storage
from spambayes import hammie
bayes = storage.open_storage ('/home/georg/hammie.db', 'dbm')
scoremaster = hammie.Hammie(bayes)
score = scoremaster.score # function!!


import Milter

from posix import getloadavg

import cfg

# Tune this?
configfile = "/etc/mail/wumi.cf"

# TODO - find out the truth about loadconfig ...

def asciistring(s):

# types.UnicodeType
    if type (s) not in [types.StringType, types.UnicodeType]:
        s=str(s)
    t=""
    for i in s:
        if ord(i) > 127:
            t+="_"
        else:
            t+=i
    return t    


class Plugin:

    """ok() meaning:
    None: Not tested
    True: OK
    False: Not OK"""
    
    def __init__ (self, milter):
        self.milter = milter
        self.status = None # None (not tested) 1 (ok) 0 (notok)
        self.reason = "Defaultplugin/headermatch"

    # ok should be overridden, ok () can be called more than once
    def ok (self):
        if self.status != None:
            return self.status # If a status has been set, return this status
        else:
            return True # default to ok if no Status has been set
        
    def get_reason (self):
        return self.reason
        

class BlockedName (Exception):
    pass

class Eom_spambayes_plugin (Plugin):

    def __init__ (self, milter):
        Plugin.__init__ (self, milter)

    def ok (self):
        if self.status != None: return self.status
        milter = self.milter

        msg = file (milter.fn)
        if self.thinkspam (msg):
            self.status = False
            self.reason = "Sorry, I think this is spam"
            milter.setreply ('554','5.7.1', self.reason)
            milter.v_returnstatus = Milter.REJECT
            return self.status

        self.status = True        
        return self.status

    def thinkspam (self, msg):
        return score (msg) > 0.75

class EnvrcptValidsender (Plugin):

    def __init__ (self, milter, addr):
        self.addr = addr
        Plugin.__init__ (self, milter)

    def ok (self):
        if self.status != None: return self.status
        milter = self.milter
        mfrom = milter.v_envfrom # already stripped of braces
        local = self.addr.split ("@")[0]
        milter.log ("ENVRCPT: to localuser: %s" % local)
        filename = "/tmp/wumi-validsender/%s.gdbm" % local

        try:
            db = gdbm.open (filename)
        except:
            milter.log ("ENVRCPT: cannot open %s" % filename)
            self.status = True
            return self.status

        if not (db.has_key ("active") and db.has_key ("bouncetext")):    
            milter.log ("ENVRCPT: missing active and bouncetext in %s" % filename)
            self.status = True

        elif db ["active"] and not (db.has_key (mfrom) or db.has_key ('@' + mfrom.split ('@')[-1])):
            self.reason = "\nRecepient refuses mail from %s:\n\n%s" % (mfrom, db ["bouncetext"])
            while "\r\n" in self.reason: self.reason = self.reason.replace ("\r\n", "\n")
            while "\r" in self.reason: self.reason = self.reason.replace ("\r", "\n")
            # self.reason = "Recepient refuses your mail" # :\n\n%s" % db ["bouncetext"]
            milter.setreply ('550', '5.7.1', *self.reason.split ("\n"))
            milter.v_returnstatus = Milter.REJECT
            self.status = False
                
        else:
            self.status = True

        return self.status    


class Eom_kolabheader_plugin (Plugin):

    def __init__ (self, milter):
        Plugin.__init__ (self, milter)

    def ok (self):
        if self.status != None: return self.status
        milter = self.milter
        msg = email.message_from_file (file (milter.fn))

        if not msg.get ("X-Kolab-Scheduling-Message"):
            # gather non-multiparts in first level in parts:
            if not msg.is_multipart ():
                parts = [msg]
            else:
                parts = []
                for m in msg.get_payload ():
                    if not m.is_multipart(): parts.append (m)
            iskolab = False
            for part in parts:            
                if part.get_content_type () == 'text/calendar':
                    iskolab = True
                    break
            if iskolab:
                milter.addheader ("X-Kolab-Scheduling-Message", "TRUE")
            else:
                if cfg.vars ["kolab_false_header"]:
                    milter.addheader ("X-Kolab-Scheduling-Message", "FALSE")
        self.status = True        
        return self.status

class Eom_blacklist_header_plugin (Plugin):

    def ok (self):
        if self.status != None: return self.status
        milter = self.milter
        for blacklist in cfg.vars ["bls"].values ():
            if milter.v_headers.has_key (blacklist.header):
                continue
            if not blacklist.islisted (milter.v_remotehostip):
                continue
            if blacklist.blockmail:
                self.status = False
                self.reason = blacklist.getheader (milter.v_remotehostip)
                milter.setreply ('554','5.7.1', self.reason)
                milter.v_returnstatus = Milter.REJECT
                return self.status
            if blacklist.add_x_header:
                header, value = blacklist.getheader (milter.v_remotehostip)
                self.milter.addheader (header, value)
        self.status = True            
        return self.status


class Eom_attachblock_plugin (Plugin):

    def __init__ (self, milter):
        Plugin.__init__ (self, milter)
    
    def ok (self):  
        """Check (against cfg "noattach") if this body is ok.
        Do not check twice, instead return the cached value self.ok
        set reason"""
        
        if self.status != None: return self.status
        milter=self.milter

        try:
            self.mimerecursion=0
            
            for m in email.message_from_file (file (milter.fn)).walk ():
                if not m.is_multipart (): self.checkAttach (m)

            # Possible Exceptions:
            # LookupError, MessageError
            
        except (Errors.MessageError, LookupError, TypeError), msg:
            self.reason = asciistring (msg)
            self.status = False
            milter.v_returnstatus = Milter.REJECT
            milter.v_keepfile=1
            milter.setreply ('554','5.7.1',"Message Format Error, please contact postmaster for analysis")
            sys.stderr.write("Captured Message '%s', Error: %s\n" % (milter.fn,self.reason))
            return self.status

        except BlockedName, msg:
            self.status = False
            self.reason = '''Forbidden Extension ".%s" in %s, see %s''' % (msg[0], \
                    asciistring(msg[1]), cfg.vars ["policyurl"])
            milter.v_returnstatus = Milter.REJECT
            milter.setreply ('554', '5.7.1', self.reason)
            return self.status

        except zlib.error, msg:
            self.status = False
            self.reason = '''Zlib Error: %s''' % msg
            milter.v_returnstatus = Milter.REJECT
            milter.setreply ('554','5.7.1', self.reason)
            return self.status

        except zipfile.BadZipfile, msg:
            self.status = False
            self.reason = '''Cannot parse .zip Attachment (%s)''' % msg
            milter.v_returnstatus = Milter.REJECT
            milter.setreply ('554','5.7.1',self.reason)
            return self.status

        except Exception, msg:
            sys.stderr.write ("Unhandled Exception: %s\n" % msg)
            traceback.print_exc (file = sys.stderr)
            sys.stderr.flush ()
            self.status = 0
            self.reason = '''Unhandled Exception - see logs'''
            milter.v_returnstatus = Milter.REJECT
            milter.setreply ('554','5.7.1', self.reason)
            return self.status

        self.status = True
        self.reason = "extensions ok"

        if cfg.vars ["attachblock_xheader"]:
            self.milter.addheader (cfg.vars ["seenheader"], "ok %s" % cfg.vars ["hostname"])

        return self.status
        
    def checkAttach (self, msg):
        """takes a non-multipart message
        return boolean"""
    
        fn = msg.get_filename ()
        if fn:
            ext = fn.split ('.')[-1].lower ()
            
            if ext in cfg.vars ["noattach"]:
                raise BlockedName, (ext, fn)
            
            # ZIP File Processing:
            elif ext == "zip":
                zipfiles = [] # list of strings
                zipfiles.append (msg.get_payload (decode = True))
                stackpushes = 1
                while zipfiles:
                    zf = zipfile.ZipFile (StringIO.StringIO (zipfiles.pop ()))
                    for fn in zf.namelist ():
                        ext = fn.split ('.') [-1].lower ()
                        if ext in cfg.vars ["noattach"]:
                            raise BlockedName, (ext, fn + "(within_zip_file)")
                        cont = zf.read (fn)  # raise Error if content not readable
                        if ext == "zip":
                            zipfiles.append (cont)
                            stackpushes += 1
                            if stackpushes > 100:
                                raise zipfile.BadZipfile, "Too many .zip files in .zip file"


class WUMilter (Milter.Milter):

    def __init__(self):
        self.v_id = Milter.uniqueID()
        self.v_remotehostname = '' 
        self.v_remotehostip = '' 
        self.o_lastplugin = Plugin (self) # even if no eom plugins are configured, the ok() method is necessary
        self.v_keepfile = False
        self.v_rblinfo = False # Do we have the info about rbl appearance of v_remotehostip
        self.reset ()

    def reset (self):
        self.cleanup ()
        self.fn = tempfile.mktemp (cfg.vars ["filtername"])
        self.fp = file (self.fn,'w')
        self.o_vir = None
        self.o_hash = md5.new()
        self.v_returnstatus = Milter.CONTINUE
        self.v_headers = {}
        self.v_aborted = None
        self.v_keepfile = False
        self.v_envfrom = ''
        self.v_envrcpt = []

    def cleanup (self):
        if not self.v_keepfile:
            try: os.remove(self.fn)
            except: pass
        else:
            try: self.log ("Keeping File", self.fn)
            except: pass  

    def log (self, *msg):
        a = '[%d]' % self.v_id
        for i in msg:
            a += ' %s' % str(i)
        syslog.syslog (a)

    def connect (self,hostname,unused,hostaddr):
        self.v_remotehostname=hostname 
        self.v_remotehostip=hostaddr[0]
        return self.v_returnstatus

    def hello (self,hostname):
        return self.v_returnstatus

    def envfrom (self, f, *str):
        self.reset ()
        self.v_envfrom = f.lstrip("<").rstrip(">").lower()
        return self.v_returnstatus

    def envrcpt (self, to, *str):

        addr = to.lstrip("<").rstrip(">").lower()
        self.v_envrcpt.append(addr)

        for pi in cfg.vars ["envrcpt_plugins"]:
            plugin = pi (self, addr)
            self.o_lastplugin = plugin
            if not plugin.ok ():
                # There's no need to continue, the mail gets rejected
                # The plugin does a setreply on self.milter and also sets
                # self.v_returnstatus
                break
        # in case of no plugins this is Plugin () from base class.__init__()
        if self.o_lastplugin.ok ():
            self.v_returnstatus = Milter.CONTINUE
            self.log ('ENVRCPT ok envfrom (%s) envrcpt (%s)' % \
                    (self.v_envfrom, addr))
        else:
            self.log ('ENVRCPT REJECT envfrom (%s) envrcpt (%s)' % \
                    (self.v_envfrom, addr))

        return self.v_returnstatus

    def header (self, name, val):
        self.fp.write ('%s: %s\n' % (name, val))
        if not self.v_headers.has_key (name):
            self.v_headers [name] = []
        self.v_headers [name].append (val)
        return self.v_returnstatus

    def eoh (self):
        self.fp.write('\n')
        return self.v_returnstatus
        
    def body (self, chunk):
        self.o_hash.update (chunk)
        self.fp.write (chunk)
        return self.v_returnstatus

    def eom (self):

        self.fp.close ()
        for pi in cfg.vars ["eom_plugins"]:
            plugin = pi (self)
            self.o_lastplugin = plugin
            if not plugin.ok ():
                # There's no need to continue, the mail gets rejected
                # The plugin does a setreply on self.milter and also sets
                # self.v_returnstatus
                break
        # in case of no plugins this is self.plugin from base class      
        if self.o_lastplugin.ok ():
            self.v_returnstatus = Milter.ACCEPT
            self.log ('Accept From Host %s (%s) envfrom (%s) envrcpt (%s)' % \
                    (self.v_remotehostname, self.v_remotehostip, self.v_envfrom, \
                    str (self.v_envrcpt) [:128]),  self.o_lastplugin.get_reason ())
        else:
            self.log ('Reject From Host %s (%s) envfrom (%s) envrcpt (%s)' % 
                    (self.v_remotehostname, self.v_remotehostip, self.v_envfrom, \
                    str (self.v_envrcpt) [:128]),  self.o_lastplugin.get_reason ())

        return self.v_returnstatus

    def close (self):
        self.cleanup ()
        return self.v_returnstatus

    def abort (self):
        self.v_aborted = 1
        self.log ('Session Aborted', self.v_remotehostname, self.v_remotehostip, \
                self.v_envfrom)
        return self.v_returnstatus


def main():

    sys.stdout.write("--------------- WUMI START ---------------\n")
    sys.stdout.flush()
    cfg.vars = cfg.Globals (configfile)
    syslog.openlog (cfg.vars ["filtername"])
    Milter.factory = WUMilter
    Milter.set_flags (Milter.ADDHDRS | Milter.CHGHDRS)
    Milter.runmilter (cfg.vars["filtername"], cfg.vars["socketname"], timeout=1800)
    print '%s: runmilter returned - shutdown' % cfg.vars["filtername"]


if __name__ == '__main__':
    main()

