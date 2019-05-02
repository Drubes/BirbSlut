#!/usr/bin/python
# -*- coding: utf-8 -*-
from dbase import *
from funcy import *
from multiprocessing import Process, Queue, current_process, freeze_support
import argparse
import requests
import logging
import base64
import time
import sys




    #d.add_req(url,timestamp,timedif,str(injected_headers),str(injected_data),status,headers,content,size)



#parsh the arguments.###########################################################
desc = "BawlSec\'s BirbSlut: \n\n"\
       "A cheap & crappy replacement for Burpsuits intruder.\n"\
       "for now it only attacks using the batterram methode.\n"\
       "and uses only lists as payloads... \n"\
       "but hey, it's faster than the community edition\n\n"\
       "anyway: it replaces the magic word BECKY with the payloads\n"\
       "from the profided list it stores the resulst in a sqlite db.\n"


parser = argparse.ArgumentParser(description=desc)
parser.add_argument('dbname',
                    metavar='<db path>',
                    type=str,
                    help='path of database')

parser.add_argument('url',
                    metavar='<url>',
                    type=str,
                    help='the target URL')

parser.add_argument('payloads',
                    metavar='<pl path>',
                    type=str,
                    help='path to the payload list')

parser.add_argument('-c',
                    dest='cookies',
                    type=str,
                    action='append',
                    help='post data   -c awsome=cookie -c uid=666')



parser.add_argument('-d',
                    dest='post_data',
                    type=str,
                    action='append',
                    help='post data   -d data=hey -d page=becky')

parser.add_argument('-g',
                    dest='get_data',
                    type=str,
                    action='append',
                    help='post data   -g q=lemme -g page=smash')


parser.add_argument('-H',
                    dest='headers',
                    type=str,
                    help='headers  -H user-agent=MozillaMoproblems -H X-forwared-for=127.0.0.1',
                    action='append')

parser.add_argument('-M',
                    dest='methode',
                    type=str,
                    choices = ["GET", "HEAD", "POST", "PUT", "DELETE","CONNECT", "OPTIONS", "TRACE"],
                    default = "GET",
                    help='Request methode.')
                    #choices = ["GET", "POST"],

parser.add_argument('-m',
                    dest='timeout',
                    type=str,
                    default = 30,
                    help='max time per request in seconds.')

parser.add_argument('--b64',
                    dest='base',
                    action='store_true',
                    help='Payloads in file are base64 encoded.')

parser.add_argument('-v',
                    dest='verbose',
                    choices = [0, 1, 2, 3, 4, 5],
                    type=int,
                    default=1,
                    help='verbosety, 5=CRITICAL 4=ERROR 3=WARNING 2=INFO 1=DEBUG 0=NOTSET')


parser.add_argument('-t',
                    dest='treads',
                    type=int,
                    default=10,
                    help='amount of treads (not implemented yet)')

args = parser.parse_args()

target      = args.url
payloadfile = args.payloads
timeout     = args.timeout
methode     = args.methode
headers     = args.headers
treads      = args.treads
dbname      = args.dbname
post_data   = args.post_data
get_data    = args.get_data
cookies     = args.cookies
is_base64   = args.base

logging.basicConfig(level=args.verbose*10)
log = logging.getLogger(__name__)

#log.logger.setLevel()


################################################################################
# drops payload returns list..
#
def drop_payload(payload):
    injected_data=inject_payload(data_dic, payload)
    injected_headers=inject_payload(header_dic, payload)
    injected_params=inject_payload(param_dic, payload)
    injected_cookies=inject_payload(cookie_dic, payload)
    timestamp = int(time.time())
    if methode == "GET":
        r = requests.get(target, headers=injected_headers, cookies=injected_cookies, params=injected_params, data=injected_data, timeout=timeout)
    if methode == "HEAD":
        r = requests.head(target, headers=injected_headers, cookies=injected_cookies, params=injected_params, data=injected_data, timeout=timeout)
    if methode == "POST":
        r = requests.post(target, headers=injected_headers, cookies=injected_cookies, params=injected_params, data=injected_data, timeout=timeout)
    if methode == "PUT":
        r = requests.put(target, headers=injected_headers, cookies=injected_cookies, params=injected_params, data=injected_data, timeout=timeout)
    if methode == "DELETE":
        r = requests.delete(target, headers=injected_headers, cookies=injected_cookies, params=injected_params, data=injected_data, timeout=timeout)
    if methode == "CONNECT":
        r = requests.connect(target, headers=injected_headers, cookies=injected_cookies, params=injected_params, data=injected_data, timeout=timeout)
    if methode == "OPTIONS":
        r = requests.options(target, headers=injected_headers, cookies=injected_cookies, params=injected_params, data=injected_data, timeout=timeout)
    if methode == "TRACE":
        r = requests.trace(target, headers=injected_headers, cookies=injected_cookies, params=injected_params, data=injected_data, timeout=timeout)
    timedif = timestamp-int(time.time())
    url = r.url
    status = int(r.status_code)
    log.debug(status)
    size = int(r.headers['Content-Length'])
    headers = str(r.headers)
    content = r.text
    #d.add_req({"url":url, "timestamp":timestamp, "timedif":timedif, "requesthead":str(injected_headers), "request":str(injected_data), "status":status, "headers":headers, "content":content, "size":size})
    return {"url":url, "timestamp":timestamp, "timedif":timedif, "requesthead":str(injected_headers), "request":str(injected_data), "status":status, "headers":headers, "content":content, "size":size}



################################################################################
# handle payloads list.
payloads = get_payloads(payloadfile)
if is_base64:
    payloads = decode_payloads(payloads)

################################################################################
# connect to database.
d = bsdb(dbname)

################################################################################
# prepair headers.
if headers != None:
    header_dic = data_to_dic(headers)
else:
    header_dic = {"user-agent":"HeybeckyLetme-smash."}

################################################################################
#  prepare post_data.
if post_data:
    data_dic = data_to_dic(post_data)
else:
    data_dic = {}

################################################################################
#  prepare post_data.
if cookies:
    cookie_dic = data_to_dic(cookies)
else:
    cookie_dic = {}

################################################################################
#  prepare get_data.
if get_data:
    param_dic = data_to_dic(get_data)
else:
    param_dic = {}

################################################################################
#  IDK what im doing.


#gekut en gepast.
def worker(input, output):
    for func, args in iter(input.get, 'STOP'):
        result = func(args)
        output.put(result)

#dit heb ik wel zelf gepruts.
def dbm(done, loads):
    for x in range(loads):
        d.add_req(done_queue.get())

freeze_support()
task_queue = Queue()
done_queue = Queue()


log.info("dropping "+str(len(payloads))+" payloads\n Using "+str(treads)+" treads")
for payload in payloads:
    #print payload[:-1]
    task_queue.put([drop_payload, payload[:-1]])

# start the tread that will write to the db.
Process(target=dbm, args=(done_queue, len(payloads))).start()

#start threads that will rape the server.
for i in range(treads):
    Process(target=worker, args=(task_queue, done_queue)).start()
    print "whoop whooop whooooppp"

#end the rapey treads.
for i in range(treads):
    task_queue.put('STOP')
