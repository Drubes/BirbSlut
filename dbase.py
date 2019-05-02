#!/usr/bin/python
# -*- coding: utf-8 -*-
import sqlite3 as lite
import logging
from funcy import *
log = logging.getLogger(__name__)
################################################################################
# BirbSlutDataBase
class bsdb():
    def __init__(self, name):
        self.filename = name
        self.connect()
        self.init_db()

    #####################################################
    # connects to database.
    def connect(self):
        try:
            log.debug("connecting to db")
            self.con = lite.connect(self.filename)
            self.cur = self.con.cursor()
        except:
            log.critical("can't connect to database")
            return 0


    ####################################################
    # sets up the table(s)
    #
    #==[req]===================================================================+
    # url | time | timedif | requesthead | request | status  | headers | content | size
    # text| int  |   int   |  text       | text    | int     | text    | text    | int


    def init_db(self):
        with self.con:
            try:
                self.cur.execute("CREATE TABLE req(url TEXT, time INT, timedif INT, requesthead TEXT, request TEXT, status INT, headers TEXT, content TEXT, size INT);")
                log.debug("created table req in "+self.filename)
                return 1
            except:
                log.warning("file "+self.filename+" already exists.\n are you sure you want to continue?")
                if yaynay():
                    return 0
                else:
                    quit()


    ####################################################
    # Add a request record.
    def add_req(self, url, time, timedif, requesthead, request, status, headers, content, size):
        # check arguments
        try:
            time+timedif+status+size+1
            url+headers+request+content+requesthead+"lalala"
        except:
            log.error("Fucked up input..")
            return
        with self.con:
            log.debug("adding request to req table.")
            req_ps = "INSERT INTO req (url, time, timedif, requesthead, request, status, headers, content,size) VALUES (?,?,?,?,?,?,?,?,?)"
            self.cur.execute(req_ps, (url, time, timedif, requesthead, request, status, headers, content,size))


    #####################################################
    # close the connection
    def close_db(self):
        with self.con:
            self.con.close()
