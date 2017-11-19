#!/usr/local/bin/python
# -*- coding: iso-8859-15 -*-
"""Holds all wumi configs"""

import ConfigParser
import os
import re
import socket
import sys
import syslog
import time
import traceback

from email import Parser
from threading import Lock

from blacklist import Blacklist
import wumi

eom_plugins = {'attachblock'  : wumi.Eom_attachblock_plugin,
               'blacklist': wumi.Eom_blacklist_header_plugin,
               'spambayes': wumi.Eom_spambayes_plugin,
               'kolab': wumi.Eom_kolabheader_plugin}

envrcpt_plugins = {'validsender': wumi.EnvrcptValidsender}

class Globals:
    """a thread-safe, reloadable config-vars dict"""

    # convention:
    # funcnames without leading _ assume an unlocked state
    # funcnames with    leading _ assume an   locked state

    def __init__ (self, cffile):

        # Here we set the vars that cannot be changed at run-time
        # Loadconfig () only sets runtime-changable vars.
        # for the others restart wumi ;-)

        self.lock = Lock ()
        self.lastupdate = time.time ()
        self.dict = {}
        globals = self.dict

        globals ["cvs_id"] = "$Id: cfg.py,v 1.18 2008/07/05 10:58:29 schurlix Exp $"
        globals ["configfile"] = cffile
        globals ["hostname"] = socket.gethostname ().split ('.') [0]
        globals ["updateseconds"] = 15
        cfparser = ConfigParser.ConfigParser ()
        cfparser.readfp (file (cffile))

        # filtername (can be set from conffile)
        globals ["filtername"] = "wumi"
        try:
            globals ["filtername"] = cfparser.get ("misc", "filtername")
        except:
            print """filtername not found in config, using '%s'""" % globals ["filtername"]

        # socketname (can be set from conffile)
        globals ["socketname"] = "/var/run/milter/%s" % globals ["filtername"]
        try:
            globals ["socketname"] = os.environ ["WUMI_SOCKET"]
            sys.stderr.write  ("ATTENTION: Using Env WUMI_SOCKET: %s\n" %  (globals ["socketname"], ))
        except KeyError: # no ENV WUMI_SOCKET
            pass
        try:
            globals ["socketname"] = cfparser.get ("misc", "socketname")
        except KeyError: # and not in cfparser  ("misc", "socketname")
            pass
        
        # volatile vars...
        self.loadconfig ()  


    def loadconfig (self):  

        self._lock ()
        try:
            globals = self.dict
            sys.stdout.write ("--------------- WUMI LOADCONFIG ---------------\n")
            sys.stdout.flush ()
            # Order of global to be filled:
            # built in default, overriden by cf-file

            cfparser = ConfigParser.ConfigParser ()
            cfparser.readfp (file (globals ["configfile"]))

            # Some common python Objects, not configurable
            # globals ["parse"] = Parser.Parser ().parse

            # Urls for SMTP Error Messages
            # maxload
            globals ["maxload"] = 10
            try:
                globals ["maxload"] = float (os.environ ["WUMI_MAXLOAD"])
                sys.stderr.write  ("I Use Env WUMI_MAXLOAD: %s" % globals ["maxload"])
            except: 
                print """maxload not in env"""
            try:
                globals ["maxload"] = cfparser.getint ("misc", "maxload")
            except:
                print """maxload not found in conf, using '%s'""" % globals ["maxload"]

            # plugins EOM
            useeomplugins = set (cfparser.get ("misc", "eom_plugins").lower ().split (",")) 
            while '' in useeomplugins: useeomplugins.remove ('')
            globals ["eom_plugins_names"] = useeomplugins
            globals ["eom_plugins"] = []
            for plugin_name in useeomplugins:
                globals ["eom_plugins"].append (eom_plugins [plugin_name])

            # plugins ENVRCPT    
            useenvrcptplugins = set (cfparser.get ("misc", "envrcpt_plugins").lower ().split (",")) 
            while '' in useenvrcptplugins: useenvrcptplugins.remove ('')
            globals ["envrcpt_plugins_names"] = useenvrcptplugins
            globals ["envrcpt_plugins"] = []
            for plugin_name in useenvrcptplugins:
                globals ["envrcpt_plugins"].append (envrcpt_plugins [plugin_name])

            # seenheader
            globals ["seenheader"] = None
            try: globals ["seenheader"] = cfparser.get ("misc", "seenheader")
            except: print """seenheader not found in config, using %s""" % globals ["seenheader"]

            # read blacklist stanza - if it is in misc/eom_plugins
            if "blacklist" in globals ["eom_plugins_names"]:
                # blacklists
                globals ["blacklists"] = set (cfparser.get ("blacklist", "blacklists").split (","))
                if '' in globals ["blacklists"]: globals ["blacklists"].remove ('')
                globals ["bls"] = {}
                for bl_stanza in globals ["blacklists"]:
                    globals ["bls"][bl_stanza] = Blacklist (cfparser, bl_stanza, globals ["seenheader"])

            # TODO hier die werdte einfüllen!!!
            # read attachblock stanza - if it is in misc/eom_plugins
            if "attachblock" in globals ["eom_plugins_names"]:
                # policy - Url
                globals ["policyurl"] = cfparser.get ("attachblock", "policyurl")

                # blocked attachments
                globals ["noattach"] = set (cfparser.get ("attachblock", "noattach").lower ().split (","))
                if '' in globals ["noattach"]: globals ["noattach"].remove ('')

                # add_x_header
                globals ["attachblock_xheader"] = cfparser.getboolean ("attachblock", "add_x_header")

            if "kolab" in globals ["eom_plugins_names"]:
                # policy - Url
                globals ["kolab_false_header"] = cfparser.getboolean ("kolab", "add_false_header")

            # print something candy
            sys.stdout.write ( \
                "Current config after loading: ----------------------------------\n")

            i = globals.keys ()
            i.sort ()
            for j in i: sys.stdout.write ("%-25s: %s\n" %  (j, globals [j]))

            sys.stdout.flush ()
            self.lastupdate = time.time ()

        finally:  
            self._unlock ()

            
    def refresh (self):

        if (time.time () - self.lastupdate) > self.dict ["updateseconds"] and \
                (os.path.getmtime (self ["configfile"]) > self.lastupdate):

            try:
                self.loadconfig ()
                
            except IOError, msg:
                # self.lastupdate is not reset, loadconfig does this
                # at the very end, but in this case we never reach that
                # point.
                sys.stderr.write ("Warning: One of the config Files is not reachable, msg and Traceback follows\n")
                print >> sys.stderr, msg
                traceback.print_exc (file = sys.stderr)
                sys.stderr.flush ()
                
            except:
                sys.stderr.write ("Warning: Cannot handle exception in loadconfig, Traceback:\n")
                traceback.print_exc (file = sys.stderr)
                sys.stderr.flush ()
                os._exit (1)


    def _lock (self):
        self.lock.acquire ()


    def _unlock (self):
        self.lock.release ()


    def __getitem__ (self, key):

        self._lock ()
        try:
            return self.dict [key]
        finally:  
            self._unlock ()

